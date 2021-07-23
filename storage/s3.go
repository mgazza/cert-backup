package storage

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/mgazza/cert-backup/errors"
	"io"
)

type S3Manager struct {
	bucket  string
	session *session.Session
}

type StorageError struct {
	InnerError error
	Err        error
}

func (e *StorageError) Error() string {
	return fmt.Sprintf("%v: %v", e.Err.Error(), e.InnerError.Error())
}

func (e *StorageError) Unwrap() error { return e.Err }

func New(region, bucket string) (*S3Manager, error) {
	sess, err := session.NewSession(
		&aws.Config{
			Region: aws.String(region),
		},
	)
	return &S3Manager{bucket: bucket, session: sess}, err
}

func (s S3Manager) Upload(name string, body io.Reader) error {
	uploader := s3manager.NewUploader(s.session)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(name),
		Body:   body,
	})
	return err
}

func (s S3Manager) Download(name string, w io.WriterAt) error {
	uploader := s3manager.NewDownloader(s.session)
	_, err := uploader.Download(w, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(name),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == s3.ErrCodeNoSuchKey {
				return &StorageError{
					InnerError: err,
					Err:        errors.ErrNotFound,
				}
			}
		}
	}

	return err
}

func (s S3Manager) List() (*s3.ListObjectsOutput, error) {
	svc := s3.New(s.session)
	return svc.ListObjects(&s3.ListObjectsInput{
		Bucket: aws.String(s.bucket),
	})
}
