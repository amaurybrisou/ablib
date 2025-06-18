//go:build integration
// +build integration

package store

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/amaurybrisou/ablib/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type TestDocument struct {
	ID   string `bson:"_id,omitempty"`
	Name string `bson:"name"`
}

func setupTestContainer(t *testing.T) (*internal.Container, uint16, error) {
	container, err := internal.NewContainer(nil, internal.ContainerConfig{
		Repository: "mongo",
		Tag:        "latest",
		Env:        []string{"MONGO_INITDB_ROOT_USERNAME=test", "MONGO_INITDB_ROOT_PASSWORD=test"},
	})
	require.NoError(t, err)

	// Wait for the container to be ready
	err = container.Retry(func() error {
		var err error
		db, err := mongo.Connect(options.Client().ApplyURI(fmt.Sprintf("mongodb://test:test@localhost:%s", container.GetPort("27017/tcp"))))
		if err != nil {
			return err
		}

		return db.Ping(context.Background(), nil)
	})

	require.NoError(t, err)

	strPort := container.GetPort("27017/tcp")
	port, err := strconv.ParseUint(strPort, 10, 16)
	require.NoError(t, err)

	return container, uint16(port), nil
}

func TestNewMongoClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	container, port, err := setupTestContainer(t)
	assert.NoError(t, err)
	defer func() {
		err := container.Purge()
		assert.NoError(t, err)
	}()

	tests := []struct {
		name    string
		opts    MongoOptions
		wantErr bool
	}{
		{
			name: "valid connection",
			opts: MongoOptions{
				Username:     "test",
				Password:     "test",
				Host:         "localhost",
				Port:         port,
				MaxPoolSize:  10,
				WriteConcern: "majority",
			},
			wantErr: false,
		},
		{
			name: "invalid credentials",
			opts: MongoOptions{
				Username:     "wrong",
				Password:     "wrong",
				Host:         "localhost",
				Port:         port,
				MaxPoolSize:  10,
				WriteConcern: "majority",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewMongoClient(ctx, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, client)
			assert.NoError(t, client.Close(ctx))
		})
	}
}

func TestMongoClientOperations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	container, port, err := setupTestContainer(t)
	assert.NoError(t, err)
	defer func() {
		err := container.Close()
		assert.NoError(t, err)
	}()

	opts := MongoOptions{
		Username:     "test",
		Password:     "test",
		Host:         "localhost",
		Port:         port,
		MaxPoolSize:  10,
		WriteConcern: "majority",
	}

	client, err := NewMongoClient(ctx, opts)
	assert.NoError(t, err)
	defer client.Close(ctx) //nolint:errcheck

	t.Run("InsertOne", func(t *testing.T) {
		doc := TestDocument{Name: "test"}
		id, err := client.InsertOne(ctx, "testdb", "testcol", bson.M{"name": doc.Name})
		assert.NoError(t, err)
		assert.NotEmpty(t, id)
	})

	t.Run("InsertMany", func(t *testing.T) {
		docs := []interface{}{
			TestDocument{Name: "test1"},
			TestDocument{Name: "test2"},
		}
		ids, err := client.InsertMany(ctx, "testdb", "testcol", docs)
		assert.NoError(t, err)
		assert.Len(t, ids, 2)
	})

	t.Run("FindOne", func(t *testing.T) {
		doc := TestDocument{Name: "findtest"}
		_, err := client.InsertOne(ctx, "testdb", "testcol", bson.M{"name": doc.Name})
		assert.NoError(t, err)

		var result TestDocument
		err = client.FindOne(ctx, "testdb", "testcol", bson.M{"name": doc.Name}, &result)
		assert.NoError(t, err)
		assert.Equal(t, "findtest", result.Name)
	})

	t.Run("UpdateOne", func(t *testing.T) {
		doc := TestDocument{Name: "updatetest"}
		_, err := client.InsertOne(ctx, "testdb", "testcol", bson.M{"name": doc.Name})
		assert.NoError(t, err)

		update := bson.M{"$set": bson.M{"name": "updated"}}
		result, err := client.UpdateOne(ctx, "testdb", "testcol", bson.M{"name": doc.Name}, update)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), result.ModifiedCount)
	})

	t.Run("DeleteOne", func(t *testing.T) {
		doc := TestDocument{Name: "deletetest"}
		_, err := client.InsertOne(ctx, "testdb", "testcol", bson.M{"name": doc.Name})
		assert.NoError(t, err)

		result, err := client.DeleteOne(ctx, "testdb", "testcol", bson.M{"name": doc.Name})
		assert.NoError(t, err)
		assert.Equal(t, int64(1), result.DeletedCount)
	})
}

func TestMongoClientErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := &MongoClient{} // nil client

	t.Run("nil client operations", func(t *testing.T) {
		_, err := client.InsertOne(ctx, "testdb", "testcol", TestDocument{})
		assert.ErrorIs(t, err, ErrNoConnection)

		_, err = client.InsertMany(ctx, "testdb", "testcol", []interface{}{})
		assert.ErrorIs(t, err, ErrNoConnection)

		err = client.FindOne(ctx, "testdb", "testcol", bson.M{}, &TestDocument{})
		assert.ErrorIs(t, err, ErrNoConnection)

		_, err = client.UpdateOne(ctx, "testdb", "testcol", bson.M{}, bson.M{})
		assert.ErrorIs(t, err, ErrNoConnection)

		_, err = client.DeleteOne(ctx, "testdb", "testcol", bson.M{})
		assert.ErrorIs(t, err, ErrNoConnection)

		err = client.Close(ctx)
		assert.NoError(t, err) // Close should not return error for nil client
	})
}
