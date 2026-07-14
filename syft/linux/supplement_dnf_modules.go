package linux

import (
	"bufio"
	"io"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

const dnfModulesGlob = "/etc/dnf/modules.d/*.module"

func supplementDnfModules(resolver file.Resolver, release *Release) {
	if release == nil {
		return
	}

	locations, err := resolver.FilesByGlob(dnfModulesGlob)
	if err != nil {
		log.Debugf("error reading %s: %v", dnfModulesGlob, err)
		return
	}

	modulesByKey := map[string]InstalledModule{}
	for _, location := range locations {
		for _, module := range readDnfModuleFile(resolver, location) {
			modulesByKey[installedModuleKey(module)] = module
		}
	}

	release.InstalledModules = sortedInstalledModules(modulesByKey)
}

func readDnfModuleFile(resolver file.Resolver, location file.Location) []InstalledModule {
	rdr, err := resolver.FileContentsByLocation(location)
	if err != nil {
		log.Debugf("error getting contents for %s: %v", location.RealPath, err)
		return nil
	}
	defer internal.CloseAndLogError(rdr, location.RealPath)

	contents, err := io.ReadAll(io.LimitReader(rdr, 5*1024*1024))
	if err != nil {
		log.Debugf("error reading %s: %v", location.RealPath, err)
		return nil
	}

	return parseDnfModuleFile(string(contents))
}

func parseDnfModuleFile(contents string) []InstalledModule {
	var modules []InstalledModule
	var current InstalledModule

	flush := func() {
		if current.Name != "" && current.Stream != "" {
			modules = append(modules, current)
		}
		current = InstalledModule{}
	}

	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			current.Name = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "name":
			current.Name = value
		case "stream":
			current.Stream = value
		case "version":
			current.Version = value
		case "context":
			current.Context = value
		case "state":
			current.State = value
		}
	}
	flush()

	return modules
}

func installedModuleKey(module InstalledModule) string {
	return strings.Join([]string{module.Name, module.Stream, module.Version, module.Context, module.State}, "\x00")
}

func sortedInstalledModules(modulesByKey map[string]InstalledModule) []InstalledModule {
	if len(modulesByKey) == 0 {
		return nil
	}

	modules := make([]InstalledModule, 0, len(modulesByKey))
	for _, module := range modulesByKey {
		modules = append(modules, module)
	}

	sort.Slice(modules, func(i, j int) bool {
		a := installedModuleKey(modules[i])
		b := installedModuleKey(modules[j])
		return a < b
	})

	return modules
}
