package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type MitreAttack struct {
	ID      string `json:"id"`
	Objects []struct {
		Aliases      []string  `json:"aliases,omitempty"`
		Created      time.Time `json:"created"`
		CreatedByRef string    `json:"created_by_ref,omitempty"`
		Definition   *struct {
			Statement string `json:"statement"`
		} `json:"definition,omitempty"`
		DefinitionType     string `json:"definition_type,omitempty"`
		Description        string `json:"description"`
		ExternalReferences []struct {
			Description string `json:"description,omitempty"`
			ExternalID  string `json:"external_id,omitempty"`
			SourceName  string `json:"source_name"`
			URL         string `json:"url,omitempty"`
		} `json:"external_references,omitempty"`
		FirstSeen       time.Time `json:"first_seen,omitempty"`
		ID              string    `json:"id"`
		IdentityClass   string    `json:"identity_class,omitempty"`
		KillChainPhases []struct {
			KillChainName string `json:"kill_chain_name"`
			PhaseName     string `json:"phase_name"`
		} `json:"kill_chain_phases,omitempty"`
		Labels                     []string  `json:"labels,omitempty"`
		LastSeen                   time.Time `json:"last_seen,omitempty"`
		Modified                   time.Time `json:"modified,omitempty"`
		Name                       string    `json:"name,omitempty"`
		ObjectMarkingRefs          []string  `json:"object_marking_refs,omitempty"`
		RelationshipType           string    `json:"relationship_type,omitempty"`
		Revoked                    bool      `json:"revoked"`
		SourceRef                  string    `json:"source_ref,omitempty"`
		TacticRefs                 []string  `json:"tactic_refs,omitempty"`
		TargetRef                  string    `json:"target_ref,omitempty"`
		Type                       string    `json:"type"`
		XMitreAliases              []string  `json:"x_mitre_aliases,omitempty"`
		XMitreAttackSpecVersion    string    `json:"x_mitre_attack_spec_version,omitempty"`
		XMitreCollectionLayers     []string  `json:"x_mitre_collection_layers,omitempty"`
		XMitreContributors         []string  `json:"x_mitre_contributors,omitempty"`
		XMitreDataSourceRef        string    `json:"x_mitre_data_source_ref,omitempty"`
		XMitreDataSources          []string  `json:"x_mitre_data_sources,omitempty"`
		XMitreDefenseBypassed      []string  `json:"x_mitre_defense_bypassed,omitempty"`
		XMitreDeprecated           bool      `json:"x_mitre_deprecated"`
		XMitreDetection            string    `json:"x_mitre_detection"`
		XMitreDomains              []string  `json:"x_mitre_domains,omitempty"`
		XMitreEffectivePermissions []string  `json:"x_mitre_effective_permissions,omitempty"`
		XMitreFirstSeenCitation    string    `json:"x_mitre_first_seen_citation,omitempty"`
		XMitreImpactType           []string  `json:"x_mitre_impact_type,omitempty"`
		XMitreIsSubtechnique       bool      `json:"x_mitre_is_subtechnique"`
		XMitreLastSeenCitation     string    `json:"x_mitre_last_seen_citation,omitempty"`
		XMitreModifiedByRef        string    `json:"x_mitre_modified_by_ref,omitempty"`
		XMitrePermissionsRequired  []string  `json:"x_mitre_permissions_required,omitempty"`
		XMitrePlatforms            []string  `json:"x_mitre_platforms,omitempty"`
		XMitreRemoteSupport        bool      `json:"x_mitre_remote_support"`
		XMitreShortname            string    `json:"x_mitre_shortname,omitempty"`
		XMitreSystemRequirements   []string  `json:"x_mitre_system_requirements,omitempty"`
		XMitreVersion              string    `json:"x_mitre_version,omitempty"`
	} `json:"objects"`
	SpecVersion string `json:"spec_version"`
	Type        string `json:"type"`
}

type ExtractedValues struct {
	Name string
	URL  string
}

var (
	attackMap    MitreAttack
	mitreJSONURL = `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`

	search = flag.String("search", "", "Needle to search. Case-insensitive.")
	file   = flag.String("file", "attack.json", "Location to JSON file to parse.")
)

func traverseTree(needle string, data MitreAttack) {
	slice := make([]ExtractedValues, 0)

	reg := regexp.MustCompile(fmt.Sprintf("(?i)%s", needle))
	for _, item := range data.Objects {
		if len(reg.FindAllString(item.Name, -1)) >= 1 {
			if len(item.ExternalReferences) >= 1 {
				for _, url := range item.ExternalReferences {
					if url.SourceName == "mitre-attack" {
						slice = append(slice, ExtractedValues{
							Name: item.Name,
							URL:  url.URL,
						})
						//fmt.Printf("Name: %s\n", item.Name)
						//fmt.Printf("URL:  %s\n", url.URL)
					}
				}
			}
		}
	}

	// Sort on our custom field
	sort.Slice(slice, func(i, j int) bool {
		return strings.ToLower(slice[i].Name) < strings.ToLower(slice[j].Name)
	})

	for _, item := range slice {
		fmt.Println()
		fmt.Printf("Name: %s\n", item.Name)
		fmt.Printf("URL:  %s\n", item.URL)
	}
}

func fileExists(file string) bool {
	_, err := os.Stat(file)

	return err == nil
}

func downloadAttackJSON(file string) ([]byte, error) {
	fmt.Printf("File %s not found. Downloading.\n", file)

	f, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := http.Get(mitreJSONURL)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func writeFile(file string, data []byte) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	f.Write(data)
	fmt.Printf("%d bytes written to %s\n", len(data), file)

	return nil
}

func flagCheck() {
	if *search == "" {
		log.Fatal("You must provide a search parameter.")
	}
}

func main() {
	flag.Parse()
	flagCheck()

	if !fileExists(*file) {
		d, err := downloadAttackJSON(*file)
		if err != nil {
			log.Fatal(err)
		}

		err = writeFile(*file, d)
		if err != nil {
			log.Fatal(err)
		}
	}

	dat, err := os.ReadFile(*file)
	if err != nil {
		return
	}

	json.Unmarshal(dat, &attackMap)

	traverseTree(*search, attackMap)
}
