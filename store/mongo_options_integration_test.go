//go:build integration
// +build integration

package store

import (
	"context"
	"strconv"
	"testing"

	"github.com/amaurybrisou/ablib/internal"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// TestDocument is used in the integration test to store simple data.
// It mirrors the document structure inserted into the database.
type TestDocument struct {
	ID   string `bson:"_id,omitempty"`
	Name string `bson:"name"`
}

// setupTestContainer spins up a Mongo container for integration tests.
func setupTestContainer(t *testing.T) (*internal.Container, uint16, error) {
	container, err := internal.NewContainer(nil, internal.ContainerConfig{
		Repository: "mongo",
		Tag:        "latest",
		Env:        []string{"MONGO_INITDB_ROOT_USERNAME=test", "MONGO_INITDB_ROOT_PASSWORD=test"},
	})
	require.NoError(t, err)

	err = container.Retry(func() error {
		ctx := context.Background()
		opts := MongoOptions{
			Username:     "test",
			Password:     "test",
			Host:         "localhost",
			Port:         uint16(container.GetPortInt16()),
			MaxPoolSize:  5,
			WriteConcern: "majority",
		}
		c, err := NewMongoClient(ctx, opts)
		if err != nil {
			return err
		}
		return c.Close(ctx)
	})
	require.NoError(t, err)

	strPort := container.GetPort("27017/tcp")
	p, err := strconv.ParseUint(strPort, 10, 16)
	require.NoError(t, err)
	return container, uint16(p), nil
}

// TestMongoClientIntegration performs a simple InsertOne round trip against a real Mongo instance.
func TestMongoClientIntegration(t *testing.T) {
	ctx := context.Background()
	container, port, err := setupTestContainer(t)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Purge() })

	opts := MongoOptions{
		Username:     "test",
		Password:     "test",
		Host:         "localhost",
		Port:         port,
		MaxPoolSize:  5,
		WriteConcern: "majority",
	}

	client, err := NewMongoClient(ctx, opts)
	require.NoError(t, err)
	defer client.Close(ctx) //nolint:errcheck

	id, err := client.InsertOne(ctx, "testdb", "testcol", bson.M{"name": "integration"})
	require.NoError(t, err)
	require.NotEmpty(t, id)
}
