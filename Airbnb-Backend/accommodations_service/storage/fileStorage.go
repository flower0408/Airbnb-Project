package storage

import (
	"context"
	"fmt"
	"github.com/colinmarc/hdfs/v2"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"io/ioutil"
	"os"
	"path"
)

type FileStorage struct {
	client *hdfs.Client
	logger *logrus.Logger
	tracer trace.Tracer
}

func New(logger *logrus.Logger, tracer trace.Tracer) (*FileStorage, error) {

	hdfsUri := os.Getenv("HDFS_URI")
	fmt.Println("HDFS_URI:", hdfsUri)

	client, err := hdfs.New(hdfsUri)
	if err != nil {
		logger.Panic(err)
		return nil, err
	}

	// Return storage handler with logger and HDFS client
	return &FileStorage{
		client: client,
		logger: logger,
		tracer: tracer,
	}, nil
}

func (fs *FileStorage) Close() {
	// Close all underlying connections to the HDFS server
	fs.client.Close()
}

func (fs *FileStorage) CreateDirectoriesStart() error {

	err := fs.client.MkdirAll(hdfsRoot, 0644)
	if err != nil {
		fs.logger.Println(err)
		return err
	}

	return nil
}

func (fs *FileStorage) CreateDirectory(folderName string) error {
	folderPath := path.Join(hdfsRoot, folderName)
	err := fs.client.MkdirAll(folderPath, 0644)
	if err != nil {
		fs.logger.Printf("Error creating directory %s: %v", folderPath, err)
		return err
	}
	return nil
}

func (fs *FileStorage) SaveImage(ctx context.Context, folderName, imageName string, imageContent []byte) error {
	ctx, span := fs.tracer.Start(ctx, "FileStorage.SaveImage")
	defer span.End()

	folderPath := path.Join(hdfsRoot, folderName)
	imagePath := path.Join(folderPath, imageName)

	if err := fs.CreateDirectory(folderName); err != nil {
		span.SetStatus(codes.Error, err.Error())
		fs.logger.Printf("Error creating directory: %v", err)
		return err
	}

	file, err := fs.client.Create(imagePath)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		fs.logger.Printf("Error creating file %s: %v", imagePath, err)
		return err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			span.SetStatus(codes.Error, closeErr.Error())
			fs.logger.Printf("Error closing file: %v", closeErr)
		}
	}()

	if _, err := file.Write(imageContent); err != nil {
		span.SetStatus(codes.Error, err.Error())
		fs.logger.Printf("Error writing image content: %v", err)
		return err
	}

	return nil
}

func (fs *FileStorage) WalkDirectories() []string {
	// Walk all files in HDFS root directory and all subdirectories
	var paths []string
	callbackFunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			fs.logger.Printf("Directory: %s\n", path)
			path = fmt.Sprintf("Directory: %s\n", path)
			paths = append(paths, path)
		} else {
			fs.logger.Printf("File: %s\n", path)
			path = fmt.Sprintf("File: %s\n", path)
			paths = append(paths, path)
		}
		return nil
	}
	fs.client.Walk(hdfsRoot, callbackFunc)
	return paths
}

func (fs *FileStorage) GetImageURLS(ctx context.Context, folderName string) ([]string, error) {
	ctx, span := fs.tracer.Start(ctx, "FileStorage.GetImageURLS")
	defer span.End()

	folderPath := path.Join(hdfsRoot, folderName)
	var imageNames []string

	callbackFunc := func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			fs.logger.Println(err)
			return err
		}
		if !info.IsDir() {
			imageName := path.Base(filePath)
			imageNames = append(imageNames, imageName)
		}
		return nil
	}

	err := fs.client.Walk(folderPath, callbackFunc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		fs.logger.Println(err)
		return nil, err
	}

	return imageNames, nil
}

func (fs *FileStorage) GetImageContent(ctx context.Context, imagePath string) ([]byte, error) {
	ctx, span := fs.tracer.Start(ctx, "FileStorage.GetImageContent")
	defer span.End()

	fullPath := path.Join(hdfsRoot, "/", imagePath)

	file, err := fs.client.Open(fullPath)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		fs.logger.Println(err)
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	imageData, err := ioutil.ReadAll(file)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		fs.logger.Println(err)
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return imageData, nil
}
