package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// --- Mocks -------------------------------------------------------

type mockSingleResult struct {
	raw []byte
	err error
}

func (m *mockSingleResult) Err() error           { return m.err }
func (m *mockSingleResult) Raw() ([]byte, error) { return m.raw, m.err }

type mockCollection struct{ mock.Mock }

func (m *mockCollection) InsertOne(ctx context.Context, doc interface{}) (*mongo.InsertOneResult, error) {
	args := m.Called(ctx, doc)
	res, _ := args.Get(0).(*mongo.InsertOneResult)
	return res, args.Error(1)
}

func (m *mockCollection) InsertMany(ctx context.Context, docs []interface{}) (*mongo.InsertManyResult, error) {
	args := m.Called(ctx, docs)
	res, _ := args.Get(0).(*mongo.InsertManyResult)
	return res, args.Error(1)
}

func (m *mockCollection) FindOne(ctx context.Context, filter interface{}) mongoSingleResult {
	args := m.Called(ctx, filter)
	sr, _ := args.Get(0).(mongoSingleResult)
	return sr
}

func (m *mockCollection) UpdateOne(ctx context.Context, filter interface{}, update interface{}) (*mongo.UpdateResult, error) {
	args := m.Called(ctx, filter, update)
	res, _ := args.Get(0).(*mongo.UpdateResult)
	return res, args.Error(1)
}

func (m *mockCollection) DeleteOne(ctx context.Context, filter interface{}) (*mongo.DeleteResult, error) {
	args := m.Called(ctx, filter)
	res, _ := args.Get(0).(*mongo.DeleteResult)
	return res, args.Error(1)
}

type mockDatabase struct{ mock.Mock }

func (m *mockDatabase) Collection(name string) mongoCollection {
	args := m.Called(name)
	col, _ := args.Get(0).(mongoCollection)
	return col
}

type mockDriver struct{ mock.Mock }

func (m *mockDriver) Database(name string) mongoDatabase {
	args := m.Called(name)
	db, _ := args.Get(0).(mongoDatabase)
	return db
}

func (m *mockDriver) Disconnect(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockDriver) Ping(ctx context.Context, rp *mongo.ReadPref) error {
	args := m.Called(ctx, rp)
	return args.Error(0)
}

// -----------------------------------------------------------------

func TestMongoClientOperations_Mocks(t *testing.T) {
	ctx := context.Background()

	driver := new(mockDriver)
	db := new(mockDatabase)
	col := new(mockCollection)

	driver.On("Database", "testdb").Return(db)
	db.On("Collection", "testcol").Return(col)

	client := &MongoClient{driver: driver}

	t.Run("InsertOne", func(t *testing.T) {
		oid := primitive.NewObjectID()
		col.On("InsertOne", ctx, bson.M{"name": "one"}).Return(&mongo.InsertOneResult{InsertedID: oid}, nil)
		id, err := client.InsertOne(ctx, "testdb", "testcol", bson.M{"name": "one"})
		assert.NoError(t, err)
		assert.Equal(t, oid.Hex(), id)
	})

	t.Run("InsertMany", func(t *testing.T) {
		ids := []interface{}{primitive.NewObjectID(), primitive.NewObjectID()}
		col.On("InsertMany", ctx, mock.Anything).Return(&mongo.InsertManyResult{InsertedIDs: ids}, nil)
		res, err := client.InsertMany(ctx, "testdb", "testcol", []interface{}{"a", "b"})
		assert.NoError(t, err)
		assert.Len(t, res, 2)
	})

	t.Run("FindOne", func(t *testing.T) {
		raw, _ := bson.Marshal(bson.M{"name": "find"})
		col.On("FindOne", ctx, bson.M{"name": "find"}).Return(&mockSingleResult{raw: raw})
		var out struct {
			Name string `bson:"name"`
		}
		err := client.FindOne(ctx, "testdb", "testcol", bson.M{"name": "find"}, &out)
		assert.NoError(t, err)
		assert.Equal(t, "find", out.Name)
	})

	t.Run("UpdateOne", func(t *testing.T) {
		updRes := &mongo.UpdateResult{ModifiedCount: 1}
		col.On("UpdateOne", ctx, bson.M{"name": "u"}, bson.M{"$set": bson.M{"name": "nu"}}).Return(updRes, nil)
		res, err := client.UpdateOne(ctx, "testdb", "testcol", bson.M{"name": "u"}, bson.M{"$set": bson.M{"name": "nu"}})
		assert.NoError(t, err)
		assert.Equal(t, int64(1), res.ModifiedCount)
	})

	t.Run("DeleteOne", func(t *testing.T) {
		delRes := &mongo.DeleteResult{DeletedCount: 1}
		col.On("DeleteOne", ctx, bson.M{"name": "d"}).Return(delRes, nil)
		res, err := client.DeleteOne(ctx, "testdb", "testcol", bson.M{"name": "d"})
		assert.NoError(t, err)
		assert.Equal(t, int64(1), res.DeletedCount)
	})
}

func TestMongoClientNoConnection(t *testing.T) {
	ctx := context.Background()
	c := &MongoClient{}

	_, err := c.InsertOne(ctx, "", "", nil)
	assert.ErrorIs(t, err, ErrNoConnection)

	_, err = c.InsertMany(ctx, "", "", nil)
	assert.ErrorIs(t, err, ErrNoConnection)

	err = c.FindOne(ctx, "", "", nil, &struct{}{})
	assert.ErrorIs(t, err, ErrNoConnection)

	_, err = c.UpdateOne(ctx, "", "", nil, nil)
	assert.ErrorIs(t, err, ErrNoConnection)

	_, err = c.DeleteOne(ctx, "", "", nil)
	assert.ErrorIs(t, err, ErrNoConnection)
}
