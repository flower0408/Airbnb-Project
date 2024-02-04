package cache

import (
	"fmt"
)

const (
	cacheImage = "%s:%s"
	cacheUrls  = "urls:%s"
)

func constructKey(accommodationId string, imageName string) string {
	return fmt.Sprintf(cacheImage, accommodationId, imageName)
}

func constructKeyUrls(accommodationId string) string {
	return fmt.Sprintf(cacheUrls, accommodationId)
}
