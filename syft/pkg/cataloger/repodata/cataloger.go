package repodata

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "repodata-cataloger"
const RepodataIsoSuffix = "iso"
const RepodataFilePattern = "**/*primary.sqlite.bz2"

type Cataloger struct{}

func NewRepodataCataloger() *Cataloger {
	return &Cataloger{}
}

func (c *Cataloger) Name() string {
	return catalogerName
}

func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	rootFiles, err := resolver.FilesByPath("")

	if len(rootFiles) == 1 && err == nil {
		inputLocation := rootFiles[0]
		if !isLocationDir(inputLocation) && strings.HasSuffix(inputLocation.RealPath, RepodataIsoSuffix) {
			log.Infof("resolver repodata from input iso: %q", inputLocation.RealPath)
			// only parse location once
			sqliteBzFilePath, sqliteBzFile, err := resolverIsoRepodataFile(inputLocation)

			if err != nil {
				return nil, nil, fmt.Errorf("failed to resolver repodata file: %w", err)
			} else if sqliteBzFilePath == "" {
				log.Warnf("unable resolver repodata from input iso: %q", inputLocation.RealPath)
				return []pkg.Package{}, nil, nil
			}

			return parseRepodata(sqliteBzFilePath, sqliteBzFile)
		}
	}

	fileMatches, err := resolver.FilesByGlob(RepodataFilePattern)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find repodata's by db file: %w", err)
	}

	for _, sqliteLocation := range fileMatches {
		sqliteBzFilePath := sqliteLocation.RealPath
		log.Infof("resolver repodata from input dir: %q", sqliteBzFilePath)

		sqliteBzFile, err := os.Open(sqliteBzFilePath)
		if err != nil {
			return nil, nil, err
		}
		defer sqliteBzFile.Close()

		// only parse one sqlite file
		discoveredPkgs, discoveredShips, err := parseRepodata(sqliteBzFilePath, sqliteBzFile)
		if err != nil {
			return nil, nil, err
		} else {
			return discoveredPkgs, discoveredShips, nil
		}
	}
	return []pkg.Package{}, nil, nil
}

func parseRepodata(sqliteBzFilePath string, sqliteBzFile io.Reader) ([]pkg.Package, []artifact.Relationship, error) {
	repodataTempDir, cleanupFn, err := createRepodataTempDir()
	defer cleanupFn()
	if err != nil {
		return nil, nil, err
	}

	unBzip2FilePath, err := unBzip2(sqliteBzFilePath, sqliteBzFile, repodataTempDir)
	if err != nil {
		return nil, nil, err
	}

	discoveredPkgs, err := parsePackagesInfo(unBzip2FilePath, sqliteBzFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse repodata for package: %w", err)
	}

	var discoveredShips []artifact.Relationship = nil
	return discoveredPkgs, discoveredShips, nil
}
