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

type connectFn func(...*options.ClientOptions) (*mongo.Client, error)

type MongoClient struct {
	addr string
	*mongo.Client
	connectFn connectFn
}

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
		opts.Username, opts.Password, opts.Host, opts.Port, opts.MaxPoolSize, opts.WriteConcern),
		connectFn: mongo.Connect}

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

	client, err := r.connectFn(opts)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mongo client")
		return err
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mongo client")
		return err
	}

	r.Client = client

	return nil
}

func (r *MongoClient) Close(ctx context.Context) error {
	if r.Client == nil {
		return nil
	}
	log.Ctx(ctx).Info().Str("address", r.addr).Msg("closing mongo client")
	return r.Disconnect(ctx)
}

func (r *MongoClient) InsertOne(ctx context.Context, dataBase, col string, doc interface{}) (string, error) {
	if r.Client == nil {
		return primitive.NilObjectID.Hex(), ErrNoConnection
	}

	res, err := r.Client.Database(dataBase).Collection(col).InsertOne(ctx, doc)
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
	if r.Client == nil {
		return nil, ErrNoConnection
	}

	res, err := r.Client.Database(dataBase).Collection(col).InsertMany(ctx, docs)
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
	if r.Client == nil {
		return ErrNoConnection
	}
	mres := r.Client.Database(dataBase).Collection(col).FindOne(ctx, filter)
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
	if r.Client == nil {
		return nil, ErrNoConnection
	}
	return r.Client.Database(dataBase).Collection(col).UpdateOne(ctx, filter, update)
}

func (r *MongoClient) DeleteOne(ctx context.Context, dataBase, col string, filter interface{}) (*mongo.DeleteResult, error) {
	if r.Client == nil {
		return nil, ErrNoConnection
	}
	return r.Client.Database(dataBase).Collection(col).DeleteOne(ctx, filter)
}
