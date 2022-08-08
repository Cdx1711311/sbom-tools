package spdxhelpers

import (
	"github.com/anchore/syft/syft/pkg"
)

func ExternalRefs(p pkg.Package, externalCounter *ExternalCounter) (externalRefs []ExternalRef) {
	externalRefs = make([]ExternalRef, 0)

	for _, c := range p.CPEs {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: SecurityReferenceCategory,
			ReferenceLocator:  pkg.CPEString(c),
			ReferenceType:     Cpe23ExternalRefType,
		})
	}

	if p.PURL != "" {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: PackageManagerReferenceCategory,
			ReferenceLocator:  p.PURL,
			ReferenceType:     PurlExternalRefType,
		})
	}

	for _, providesPurl := range p.ProvidesPurls {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: ProvideManagerReferenceCategory,
			ReferenceLocator:  providesPurl,
			ReferenceType:     PurlExternalRefType,
		})
		externalCounter.ProvideMap[providesPurl] = p.Name
	}

	pkgExternalList := []string{}
	for _, externalPurl := range p.ExtPkgPurls {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: ExternalManagerReferenceCategory,
			ReferenceLocator:  externalPurl,
			ReferenceType:     PurlExternalRefType,
		})
		externalCounter.ExternalMap[externalPurl] = p.Name
		pkgExternalList = append(pkgExternalList, externalPurl)
	}
	externalCounter.ExternalPkgMap[p.Name] = pkgExternalList

	return externalRefs
}
