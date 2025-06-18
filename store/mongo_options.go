package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

var (
	ErrNoConnection      = errors.New("mongo client not connected")
	ErrInvalidID         = errors.New("invalid document ID type")
	ErrNoDocuments       = errors.New("no documents found")
	ErrDecodingRawResult = errors.New("error decoding raw result")
)

// MongoStore exposes the methods used to interact with a MongoDB backend. It
// is implemented by MongoClient and can be mocked in tests.
type MongoStore interface {
	InsertOne(ctx context.Context, dataBase, col string, doc interface{}) (string, error)
	InsertMany(ctx context.Context, dataBase, col string, docs []interface{}) ([]string, error)
	FindOne(ctx context.Context, dataBase, col string, filter interface{}, result interface{}) error
	UpdateOne(ctx context.Context, dataBase, col string, filter interface{}, update interface{}) (*mongo.UpdateResult, error)
	DeleteOne(ctx context.Context, dataBase, col string, filter interface{}) (*mongo.DeleteResult, error)
	Close(ctx context.Context) error
}

// mongoDriver abstracts the subset of go.mongodb.org/mongo-driver functionality
// used by MongoClient. It allows injecting a mock implementation in tests.
type mongoDriver interface {
	Database(string) mongoDatabase
	Disconnect(context.Context) error
	Ping(context.Context, *readpref.ReadPref) error
}

type mongoDatabase interface {
	Collection(string) mongoCollection
}

type mongoCollection interface {
	InsertOne(context.Context, interface{}) (*mongo.InsertOneResult, error)
	InsertMany(context.Context, []interface{}) (*mongo.InsertManyResult, error)
	FindOne(context.Context, interface{}) mongoSingleResult
	UpdateOne(context.Context, interface{}, interface{}) (*mongo.UpdateResult, error)
	DeleteOne(context.Context, interface{}) (*mongo.DeleteResult, error)
}

type mongoSingleResult interface {
	Err() error
	Raw() ([]byte, error)
}

type mongoClientDriver struct{ *mongo.Client }

func (m mongoClientDriver) Database(name string) mongoDatabase {
	return mongoDatabaseDriver{m.Client.Database(name)}
}

func (m mongoClientDriver) Disconnect(ctx context.Context) error { return m.Client.Disconnect(ctx) }
func (m mongoClientDriver) Ping(ctx context.Context, rp *readpref.ReadPref) error {
	return m.Client.Ping(ctx, rp)
}

type mongoDatabaseDriver struct{ *mongo.Database }

func (d mongoDatabaseDriver) Collection(name string) mongoCollection {
	return mongoCollectionDriver{d.Database.Collection(name)}
}

type mongoCollectionDriver struct{ *mongo.Collection }

func (c mongoCollectionDriver) InsertOne(ctx context.Context, doc interface{}) (*mongo.InsertOneResult, error) {
	return c.Collection.InsertOne(ctx, doc)
}

func (c mongoCollectionDriver) InsertMany(ctx context.Context, docs []interface{}) (*mongo.InsertManyResult, error) {
	return c.Collection.InsertMany(ctx, docs)
}

func (c mongoCollectionDriver) FindOne(ctx context.Context, filter interface{}) mongoSingleResult {
	return mongoSingleResultDriver{c.Collection.FindOne(ctx, filter)}
}

func (c mongoCollectionDriver) UpdateOne(ctx context.Context, filter interface{}, update interface{}) (*mongo.UpdateResult, error) {
	return c.Collection.UpdateOne(ctx, filter, update)
}

func (c mongoCollectionDriver) DeleteOne(ctx context.Context, filter interface{}) (*mongo.DeleteResult, error) {
	return c.Collection.DeleteOne(ctx, filter)
}

type mongoSingleResultDriver struct{ *mongo.SingleResult }

func (s mongoSingleResultDriver) Err() error           { return s.SingleResult.Err() }
func (s mongoSingleResultDriver) Raw() ([]byte, error) { return s.SingleResult.Raw() }

type MongoClient struct {
	addr string
	*mongo.Client
	driver mongoDriver
}

// Ensure MongoClient implements MongoStore.
var _ MongoStore = (*MongoClient)(nil)

type MongoOptions struct {
	Username     string
	Password     string
	Host         string
	Port         uint16
	MaxPoolSize  int
	WriteConcern string
}

func NewMongoClient(ctx context.Context, opts MongoOptions) (*MongoClient, error) {
	r := &MongoClient{addr: fmt.Sprintf("mongodb://%s:%s@%s:%d/?maxPoolSize=%d&w=%s",
		opts.Username, opts.Password, opts.Host, opts.Port, opts.MaxPoolSize, opts.WriteConcern)}

	err := r.start(ctx)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mongo client")
		return nil, err
	}

	return r, nil
}

func (r *MongoClient) start(ctx context.Context) error {
	log.Ctx(ctx).Info().Msg("start mongo client")

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	opts := options.Client()
	opts.ApplyURI(r.addr)
	opts.SetConnectTimeout(30 * time.Second)
	opts.SetTimeout(10 * time.Second)

	client, err := mongo.Connect(opts)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mongo client")
		return err
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mongo client")
		return err
	}

	r.Client = client
	r.driver = mongoClientDriver{client}

	return nil
}

func (r *MongoClient) Close(ctx context.Context) error {
	if r.Client == nil {
		return nil
	}
	log.Ctx(ctx).Info().Str("address", r.addr).Msg("closing mongo client")
	return r.driver.Disconnect(ctx)
}

func (r *MongoClient) InsertOne(ctx context.Context, dataBase, col string, doc interface{}) (string, error) {
	if r.driver == nil {
		return primitive.NilObjectID.Hex(), ErrNoConnection
	}

	res, err := r.driver.Database(dataBase).Collection(col).InsertOne(ctx, doc)
	if err != nil {
		return "", err
	}
	switch v := res.InsertedID.(type) {
	case string:
		return v, nil
	case primitive.ObjectID:
		return v.Hex(), nil
	case bson.ObjectID:
		return v.Hex(), nil
	default:
		return primitive.NilObjectID.Hex(), ErrInvalidID
	}
}

func (r *MongoClient) InsertMany(ctx context.Context, dataBase, col string, docs []interface{}) ([]string, error) {
	if r.driver == nil {
		return nil, ErrNoConnection
	}

	res, err := r.driver.Database(dataBase).Collection(col).InsertMany(ctx, docs)
	if err != nil {
		return nil, err
	}

	ids := make([]string, len(res.InsertedIDs))
	for i, o := range res.InsertedIDs {
		switch v := o.(type) {
		case string:
			ids[i] = v
		case primitive.ObjectID:
			ids[i] = v.Hex()
		case bson.ObjectID:
			ids[i] = v.Hex()
		default:
			return nil, ErrInvalidID
		}
	}
	return ids, nil
}

func (r *MongoClient) FindOne(ctx context.Context, dataBase, col string, filter interface{}, result interface{}) error {
	if r.driver == nil {
		return ErrNoConnection
	}
	mres := r.driver.Database(dataBase).Collection(col).FindOne(ctx, filter)
	if mres.Err() != nil {
		return mres.Err()
	}

	rbytes, err := mres.Raw()
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return ErrNoDocuments
		}
		return ErrDecodingRawResult
	}

	decoder := bson.NewDecoder(bson.NewDocumentReader(bytes.NewReader(rbytes)))
	decoder.ObjectIDAsHexString()
	err = decoder.Decode(result)

	return err
}

func (r *MongoClient) UpdateOne(ctx context.Context, dataBase, col string, filter interface{}, update interface{}) (*mongo.UpdateResult, error) {
	if r.driver == nil {
		return nil, ErrNoConnection
	}
	return r.driver.Database(dataBase).Collection(col).UpdateOne(ctx, filter, update)
}

func (r *MongoClient) DeleteOne(ctx context.Context, dataBase, col string, filter interface{}) (*mongo.DeleteResult, error) {
	if r.driver == nil {
		return nil, ErrNoConnection
	}
	return r.driver.Database(dataBase).Collection(col).DeleteOne(ctx, filter)
}
