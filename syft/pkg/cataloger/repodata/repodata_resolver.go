package repodata

import (
	"compress/bzip2"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"

	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/filesystem"
)

// FIXME 此处路径分隔符，在windows场景下，无法适配ISO内部路径
const ISO_PATH_SEPARATOR = "/"
const ISO_REPODATA_FOLDER_NAME = "repodata"
const SQLITE_FILE_NAME_SUFFIX = "-primary.sqlite.bz2"

func resolverIsoRepodataFile(inputLocation source.Location) (string, io.Reader, error) {
	isoPath := inputLocation.RealPath

	// mount iso to filesystem
	disk, err := diskfs.OpenWithMode(isoPath, diskfs.ReadOnly)
	if err != nil {
		log.Error(err)
		return "", nil, err
	}

	fs, err := disk.GetFilesystem(0)
	if err != nil {
		log.Error(err)
		return "", nil, err
	}

	return findRepodataForIso(fs)
}

func findRepodataForIso(fs filesystem.FileSystem) (string, io.Reader, error) {
	repodataIsoPath := strings.Join([]string{"", ISO_REPODATA_FOLDER_NAME}, ISO_PATH_SEPARATOR)
	files, err := fs.ReadDir(repodataIsoPath)
	if err != nil {
		return "", nil, err
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), SQLITE_FILE_NAME_SUFFIX) {
			continue
		}

		sqliteBzFilePath := strings.Join([]string{repodataIsoPath, file.Name()}, ISO_PATH_SEPARATOR)
		// TODO readonly模式打开，是否可以不close
		sqliteBzFile, err := fs.OpenFile(sqliteBzFilePath, os.O_RDONLY)
		if err != nil {
			return "", nil, err
		}
		return sqliteBzFilePath, sqliteBzFile, nil
	}
	return "", nil, nil
}

func isLocationDir(location source.Location) bool {
	fileMeta, err := os.Stat(location.RealPath)
	if err != nil {
		log.Warnf("path is not valid (%s): %+v", location.RealPath, err)
		return false
	}
	return fileMeta.IsDir()
}

func createRepodataTempDir() (string, func(), error) {
	// create temp dir for sqlite file
	tempDir, err := ioutil.TempDir("", internal.ApplicationName+"-repodata")
	if err != nil {
		log.Errorf("failed to create temp dir: %+v", err)
		return "", func() {}, err
	}

	cleanupFn := func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			log.Errorf("unable to cleanup repodata tempdir: %+v", err)
		}
	}

	repodataTempPath := filepath.Join(tempDir, ISO_REPODATA_FOLDER_NAME)
	if createErr := createDirIfNotExist(repodataTempPath); createErr != nil {
		log.Errorf("failed to create repodata dir: %+v", err)
		return "", cleanupFn, err
	}

	// FIXME: remove Println
	fmt.Printf("repodata temp dir: %s \n", repodataTempPath)
	log.Infof("repodata temp dir: %s", repodataTempPath)
	return repodataTempPath, cleanupFn, nil
}

func unBzip2(bzip2FilePath string, bzip2File io.Reader, unzipDir string) (string, error) {
	bzip2FileName := filepath.Base(bzip2FilePath)
	unBzip2FileName := strings.TrimSuffix(bzip2FileName, ".bz2")
	unBzip2FilePath := filepath.Join(unzipDir, unBzip2FileName)
	dstWriter, err := os.Create(unBzip2FilePath)
	if err != nil {
		return unBzip2FilePath, err
	}
	defer dstWriter.Close()

	sourceReader := bzip2.NewReader(bzip2File)

	if err := file.SafeCopy(dstWriter, sourceReader); err != nil {
		return unBzip2FilePath, fmt.Errorf("unable to copy source=%q for tar=%q: %w", bzip2File, unBzip2FilePath, err)
	}

	return unBzip2FilePath, nil
}

func createDirIfNotExist(targetPath string) error {
	existing, err := os.Open(targetPath)
	if err == nil {
		defer existing.Close()
		s, err := existing.Stat()
		if err != nil {
			return err
		}

		if !s.IsDir() {
			return fmt.Errorf("%s already exists and is a file", targetPath)
		}
	} else if os.IsNotExist(err) {
		if err = os.Mkdir(targetPath, 0755); err != nil {
			return err
		}
	}
	return err
}
