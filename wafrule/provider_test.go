package wafrule

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/structure"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/terraform-providers/terraform-provider-wafrule/wafrule/internal/envvar"
)

const (
	// Provider name for single configuration testing
	ProviderNameWafrule = "wafrule"

	// Provider name for alternate configuration testing
	ProviderNameWafruleAlternate = "wafrulealternate"

	// Provider name for alternate account and alternate region configuration testing
	ProviderNameWafruleAlternateAccountAlternateRegion = "wafrulealternateaccountalternateregion"

	// Provider name for alternate account and same region configuration testing
	ProviderNameWafruleAlternateAccountSameRegion = "wafrulealternateaccountsameregion"

	// Provider name for same account and alternate region configuration testing
	ProviderNameWafruleSameAccountAlternateRegion = "wafrulesameaccountalternateregion"

	// Provider name for third configuration testing
	ProviderNameWafruleThird = "wafrulethird"
)

const rfc3339RegexPattern = `^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?([Zz]|([+-]([01][0-9]|2[0-3]):[0-5][0-9]))$`

// TestAccSkip implements a wrapper for (*testing.T).Skip() to prevent unused linting reports
//
// Reference: https://github.com/dominikh/go-tools/issues/633#issuecomment-606560616
var TestAccSkip = func(t *testing.T, message string) {
	t.Skip(message)
}

// testAccProviders is a static map containing only the main provider instance.
//
// Deprecated: Terraform Plugin SDK version 2 uses TestCase.ProviderFactories
// but supports this value in TestCase.Providers for backwards compatibility.
// In the future Providers: testAccProviders will be changed to
// ProviderFactories: testAccProviderFactories
var testAccProviders map[string]*schema.Provider

// testAccProviderFactories is a static map containing only the main provider instance
//
// Use other testAccProviderFactories functions, such as testAccProviderFactoriesAlternate,
// for tests requiring special provider configurations.
var testAccProviderFactories map[string]func() (*schema.Provider, error)

// testAccProvider is the "main" provider instance
//
// This Provider can be used in testing code for API calls without requiring
// the use of saving and referencing specific ProviderFactories instances.
//
// testAccPreCheck(t) must be called before using this provider instance.
var testAccProvider *schema.Provider

// testAccProviderConfigure ensures testAccProvider is only configured once
//
// The testAccPreCheck(t) function is invoked for every test and this prevents
// extraneous reconfiguration to the same values each time. However, this does
// not prevent reconfiguration that may happen should the address of
// testAccProvider be errantly reused in ProviderFactories.
var testAccProviderConfigure sync.Once

func init() {
	testAccProvider = Provider()

	testAccProviders = map[string]*schema.Provider{
		ProviderNameWafrule: testAccProvider,
	}

	// Always allocate a new provider instance each invocation, otherwise gRPC
	// ProviderConfigure() can overwrite configuration during concurrent testing.
	testAccProviderFactories = map[string]func() (*schema.Provider, error){
		ProviderNameWafrule: func() (*schema.Provider, error) { return Provider(), nil }, //nolint:unparam
	}
}

// testAccProviderFactoriesInit creates ProviderFactories for the provider under testing.
func testAccProviderFactoriesInit(providers *[]*schema.Provider, providerNames []string) map[string]func() (*schema.Provider, error) {
	var factories = make(map[string]func() (*schema.Provider, error), len(providerNames))

	for _, name := range providerNames {
		p := Provider()

		factories[name] = func() (*schema.Provider, error) { //nolint:unparam
			return p, nil
		}

		if providers != nil {
			*providers = append(*providers, p)
		}
	}

	return factories
}

// testAccProviderFactoriesInternal creates ProviderFactories for provider configuration testing
//
// This should only be used for TestAccWafruleProvider_ tests which need to
// reference the provider instance itself. Other testing should use
// testAccProviderFactories or other related functions.
func testAccProviderFactoriesInternal(providers *[]*schema.Provider) map[string]func() (*schema.Provider, error) {
	return testAccProviderFactoriesInit(providers, []string{ProviderNameWafrule})
}

// testAccProviderFactoriesAlternate creates ProviderFactories for cross-account and cross-region configurations
//
// For cross-region testing: Typically paired with testAccMultipleRegionPreCheck and testAccAlternateRegionProviderConfig.
//
// For cross-account testing: Typically paired with testAccAlternateAccountPreCheck and testAccAlternateAccountProviderConfig.
func testAccProviderFactoriesAlternate(providers *[]*schema.Provider) map[string]func() (*schema.Provider, error) {
	return testAccProviderFactoriesInit(providers, []string{
		ProviderNameWafrule,
		ProviderNameWafruleAlternate,
	})
}

// testAccProviderFactoriesAlternateAccountAndAlternateRegion creates ProviderFactories for cross-account and cross-region configurations
//
// Usage typically paired with testAccMultipleRegionPreCheck, testAccAlternateAccountPreCheck,
// and testAccAlternateAccountAndAlternateRegionProviderConfig.
func testAccProviderFactoriesAlternateAccountAndAlternateRegion(providers *[]*schema.Provider) map[string]func() (*schema.Provider, error) {
	return testAccProviderFactoriesInit(providers, []string{
		ProviderNameWafrule,
		ProviderNameWafruleAlternateAccountAlternateRegion,
		ProviderNameWafruleAlternateAccountSameRegion,
		ProviderNameWafruleSameAccountAlternateRegion,
	})
}

// testAccProviderFactoriesMultipleRegion creates ProviderFactories for the number of region configurations
//
// Usage typically paired with testAccMultipleRegionPreCheck and testAccMultipleRegionProviderConfig.
func testAccProviderFactoriesMultipleRegion(providers *[]*schema.Provider, regions int) map[string]func() (*schema.Provider, error) {
	providerNames := []string{
		ProviderNameWafrule,
		ProviderNameWafruleAlternate,
	}

	if regions >= 3 {
		providerNames = append(providerNames, ProviderNameWafruleThird)
	}

	return testAccProviderFactoriesInit(providers, providerNames)
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = Provider()
}

func TestReverseDns(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "amazonaws.com",
			input:    "amazonaws.com",
			expected: "com.amazonaws",
		},
		{
			name:     "amazonaws.com.cn",
			input:    "amazonaws.com.cn",
			expected: "cn.com.amazonaws",
		},
		{
			name:     "sc2s.sgov.gov",
			input:    "sc2s.sgov.gov",
			expected: "gov.sgov.sc2s",
		},
		{
			name:     "c2s.ic.gov",
			input:    "c2s.ic.gov",
			expected: "gov.ic.c2s",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {

			if got, want := ReverseDns(testCase.input), testCase.expected; got != want {
				t.Errorf("got: %s, expected: %s", got, want)
			}
		})
	}
}

func testAccWafruleProviderConfigRegion(region string) string {
	//lintignore:AT004
	return fmt.Sprintf(`
provider "wafrule" {
  region                      = %[1]q
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}
`, region)
}

// testAccPreCheck verifies and sets required provider testing configuration
//
// This PreCheck function should be present in every acceptance test. It allows
// test configurations to omit a provider configuration with region and ensures
// testing functions that attempt to call AWS APIs are previously configured.
//
// These verifications and configuration are preferred at this level to prevent
// provider developers from experiencing less clear errors for every test.
func testAccPreCheck(t *testing.T) {
	// Since we are outside the scope of the Terraform configuration we must
	// call Configure() to properly initialize the provider configuration.
	testAccProviderConfigure.Do(func() {
		envvar.TestFailIfAllEmpty(t, []string{envvar.AwsProfile, envvar.AwsAccessKeyId, envvar.AwsContainerCredentialsFullUri}, "credentials for running acceptance testing")

		if os.Getenv(envvar.AwsAccessKeyId) != "" {
			envvar.TestFailIfEmpty(t, envvar.AwsSecretAccessKey, "static credentials value when using "+envvar.AwsAccessKeyId)
		}

		// Setting the AWS_DEFAULT_REGION environment variable here allows all tests to omit
		// a provider configuration with a region. This defaults to us-west-2 for provider
		// developer simplicity and has been in the codebase for a very long time.
		//
		// This handling must be preserved until either:
		//   * AWS_DEFAULT_REGION is required and checked above (should mention us-west-2 default)
		//   * Region is automatically handled via shared AWS configuration file and still verified
		region := testAccGetRegion()
		os.Setenv(envvar.AwsDefaultRegion, region)

		err := testAccProvider.Configure(context.Background(), terraform.NewResourceConfigRaw(nil))
		if err != nil {
			t.Fatal(err)
		}
	})
}

// testAccWafruleProviderAccountID returns the account ID of an AWS provider
func testAccWafruleProviderAccountID(provider *schema.Provider) string {
	if provider == nil {
		log.Print("[DEBUG] Unable to read account ID from test provider: empty provider")
		return ""
	}
	if provider.Meta() == nil {
		log.Print("[DEBUG] Unable to read account ID from test provider: unconfigured provider")
		return ""
	}
	client, ok := provider.Meta().(*AWSClient)
	if !ok {
		log.Print("[DEBUG] Unable to read account ID from test provider: non-AWS or unconfigured AWS provider")
		return ""
	}
	return client.accountid
}

// testAccCheckResourceAttrAccountID ensures the Terraform state exactly matches the account ID
func testAccCheckResourceAttrAccountID(resourceName, attributeName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		return resource.TestCheckResourceAttr(resourceName, attributeName, testAccGetAccountID())(s)
	}
}

// testAccCheckResourceAttrRegionalARN ensures the Terraform state exactly matches a formatted ARN with region
func testAccCheckResourceAttrRegionalARN(resourceName, attributeName, arnService, arnResource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attributeValue := arn.ARN{
			AccountID: testAccGetAccountID(),
			Partition: testAccGetPartition(),
			Region:    testAccGetRegion(),
			Resource:  arnResource,
			Service:   arnService,
		}.String()
		return resource.TestCheckResourceAttr(resourceName, attributeName, attributeValue)(s)
	}
}

// testAccCheckResourceAttrRegionalARNNoAccount ensures the Terraform state exactly matches a formatted ARN with region but without account ID
func testAccCheckResourceAttrRegionalARNNoAccount(resourceName, attributeName, arnService, arnResource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attributeValue := arn.ARN{
			Partition: testAccGetPartition(),
			Region:    testAccGetRegion(),
			Resource:  arnResource,
			Service:   arnService,
		}.String()
		return resource.TestCheckResourceAttr(resourceName, attributeName, attributeValue)(s)
	}
}

// testAccCheckResourceAttrRegionalARNAccountID ensures the Terraform state exactly matches a formatted ARN with region and specific account ID
func testAccCheckResourceAttrRegionalARNAccountID(resourceName, attributeName, arnService, accountID, arnResource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attributeValue := arn.ARN{
			AccountID: accountID,
			Partition: testAccGetPartition(),
			Region:    testAccGetRegion(),
			Resource:  arnResource,
			Service:   arnService,
		}.String()
		return resource.TestCheckResourceAttr(resourceName, attributeName, attributeValue)(s)
	}
}

// testAccCheckResourceAttrRegionalHostname ensures the Terraform state exactly matches a formatted DNS hostname with region and partition DNS suffix
func testAccCheckResourceAttrRegionalHostname(resourceName, attributeName, serviceName, hostnamePrefix string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		hostname := fmt.Sprintf("%s.%s.%s.%s", hostnamePrefix, serviceName, testAccGetRegion(), testAccGetPartitionDNSSuffix())

		return resource.TestCheckResourceAttr(resourceName, attributeName, hostname)(s)
	}
}

// testAccCheckResourceAttrRegionalHostnameService ensures the Terraform state exactly matches a service DNS hostname with region and partition DNS suffix
//
// For example: ec2.us-west-2.amazonaws.com
func testAccCheckResourceAttrRegionalHostnameService(resourceName, attributeName, serviceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		hostname := fmt.Sprintf("%s.%s.%s", serviceName, testAccGetRegion(), testAccGetPartitionDNSSuffix())

		return resource.TestCheckResourceAttr(resourceName, attributeName, hostname)(s)
	}
}

// testAccCheckResourceAttrRegionalReverseDnsService ensures the Terraform state exactly matches a service reverse DNS hostname with region and partition DNS suffix
//
// For example: com.amazonaws.us-west-2.s3
func testAccCheckResourceAttrRegionalReverseDnsService(resourceName, attributeName, serviceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		reverseDns := fmt.Sprintf("%s.%s.%s", testAccGetPartitionReverseDNSPrefix(), testAccGetRegion(), serviceName)

		return resource.TestCheckResourceAttr(resourceName, attributeName, reverseDns)(s)
	}
}

// testAccCheckResourceAttrHostnameWithPort ensures the Terraform state regexp matches a formatted DNS hostname with prefix, partition DNS suffix, and given port
func testAccCheckResourceAttrHostnameWithPort(resourceName, attributeName, serviceName, hostnamePrefix string, port int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// kafka broker example: "ec2-12-345-678-901.compute-1.amazonaws.com:2345"
		hostname := fmt.Sprintf("%s.%s.%s:%d", hostnamePrefix, serviceName, testAccGetPartitionDNSSuffix(), port)

		return resource.TestCheckResourceAttr(resourceName, attributeName, hostname)(s)
	}
}

// testAccMatchResourceAttrAccountID ensures the Terraform state regexp matches an account ID
func testAccMatchResourceAttrAccountID(resourceName, attributeName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		return resource.TestMatchResourceAttr(resourceName, attributeName, regexp.MustCompile(`^\d{12}$`))(s)
	}
}

// testAccMatchResourceAttrRegionalARN ensures the Terraform state regexp matches a formatted ARN with region
func testAccMatchResourceAttrRegionalARN(resourceName, attributeName, arnService string, arnResourceRegexp *regexp.Regexp) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		arnRegexp := arn.ARN{
			AccountID: testAccGetAccountID(),
			Partition: testAccGetPartition(),
			Region:    testAccGetRegion(),
			Resource:  arnResourceRegexp.String(),
			Service:   arnService,
		}.String()

		attributeMatch, err := regexp.Compile(arnRegexp)

		if err != nil {
			return fmt.Errorf("Unable to compile ARN regexp (%s): %w", arnRegexp, err)
		}

		return resource.TestMatchResourceAttr(resourceName, attributeName, attributeMatch)(s)
	}
}

// testAccMatchResourceAttrRegionalARNNoAccount ensures the Terraform state regexp matches a formatted ARN with region but without account ID
func testAccMatchResourceAttrRegionalARNNoAccount(resourceName, attributeName, arnService string, arnResourceRegexp *regexp.Regexp) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		arnRegexp := arn.ARN{
			Partition: testAccGetPartition(),
			Region:    testAccGetRegion(),
			Resource:  arnResourceRegexp.String(),
			Service:   arnService,
		}.String()

		attributeMatch, err := regexp.Compile(arnRegexp)

		if err != nil {
			return fmt.Errorf("Unable to compile ARN regexp (%s): %s", arnRegexp, err)
		}

		return resource.TestMatchResourceAttr(resourceName, attributeName, attributeMatch)(s)
	}
}

// testAccMatchResourceAttrRegionalARNAccountID ensures the Terraform state regexp matches a formatted ARN with region and specific account ID
func testAccMatchResourceAttrRegionalARNAccountID(resourceName, attributeName, arnService, accountID string, arnResourceRegexp *regexp.Regexp) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		arnRegexp := arn.ARN{
			AccountID: accountID,
			Partition: testAccGetPartition(),
			Region:    testAccGetRegion(),
			Resource:  arnResourceRegexp.String(),
			Service:   arnService,
		}.String()

		attributeMatch, err := regexp.Compile(arnRegexp)

		if err != nil {
			return fmt.Errorf("Unable to compile ARN regexp (%s): %w", arnRegexp, err)
		}

		return resource.TestMatchResourceAttr(resourceName, attributeName, attributeMatch)(s)
	}
}

// testAccMatchResourceAttrRegionalHostname ensures the Terraform state regexp matches a formatted DNS hostname with region and partition DNS suffix
func testAccMatchResourceAttrRegionalHostname(resourceName, attributeName, serviceName string, hostnamePrefixRegexp *regexp.Regexp) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		hostnameRegexpPattern := fmt.Sprintf("%s\\.%s\\.%s\\.%s$", hostnamePrefixRegexp.String(), serviceName, testAccGetRegion(), testAccGetPartitionDNSSuffix())

		hostnameRegexp, err := regexp.Compile(hostnameRegexpPattern)

		if err != nil {
			return fmt.Errorf("Unable to compile hostname regexp (%s): %w", hostnameRegexp, err)
		}

		return resource.TestMatchResourceAttr(resourceName, attributeName, hostnameRegexp)(s)
	}
}

// testAccCheckResourceAttrGlobalARN ensures the Terraform state exactly matches a formatted ARN without region
func testAccCheckResourceAttrGlobalARN(resourceName, attributeName, arnService, arnResource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attributeValue := arn.ARN{
			AccountID: testAccGetAccountID(),
			Partition: testAccGetPartition(),
			Resource:  arnResource,
			Service:   arnService,
		}.String()
		return resource.TestCheckResourceAttr(resourceName, attributeName, attributeValue)(s)
	}
}

// testAccCheckResourceAttrGlobalARNNoAccount ensures the Terraform state exactly matches a formatted ARN without region or account ID
func testAccCheckResourceAttrGlobalARNNoAccount(resourceName, attributeName, arnService, arnResource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attributeValue := arn.ARN{
			Partition: testAccGetPartition(),
			Resource:  arnResource,
			Service:   arnService,
		}.String()
		return resource.TestCheckResourceAttr(resourceName, attributeName, attributeValue)(s)
	}
}

// testAccCheckResourceAttrGlobalARNAccountID ensures the Terraform state exactly matches a formatted ARN without region and with specific account ID
func testAccCheckResourceAttrGlobalARNAccountID(resourceName, attributeName, accountID, arnService, arnResource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attributeValue := arn.ARN{
			AccountID: accountID,
			Partition: testAccGetPartition(),
			Resource:  arnResource,
			Service:   arnService,
		}.String()
		return resource.TestCheckResourceAttr(resourceName, attributeName, attributeValue)(s)
	}
}

// testAccMatchResourceAttrGlobalARN ensures the Terraform state regexp matches a formatted ARN without region
func testAccMatchResourceAttrGlobalARN(resourceName, attributeName, arnService string, arnResourceRegexp *regexp.Regexp) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		arnRegexp := arn.ARN{
			AccountID: testAccGetAccountID(),
			Partition: testAccGetPartition(),
			Resource:  arnResourceRegexp.String(),
			Service:   arnService,
		}.String()

		attributeMatch, err := regexp.Compile(arnRegexp)

		if err != nil {
			return fmt.Errorf("Unable to compile ARN regexp (%s): %w", arnRegexp, err)
		}

		return resource.TestMatchResourceAttr(resourceName, attributeName, attributeMatch)(s)
	}
}

// testAccCheckResourceAttrRegionalARNIgnoreRegionAndAccount ensures the Terraform state exactly matches a formatted ARN with region without specifying the region or account
func testAccCheckResourceAttrRegionalARNIgnoreRegionAndAccount(resourceName, attributeName, arnService, arnResource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		arnRegexp := arn.ARN{
			AccountID: awsAccountIDRegexpInternalPattern,
			Partition: testAccGetPartition(),
			Region:    awsRegionRegexpInternalPattern,
			Resource:  arnResource,
			Service:   arnService,
		}.String()

		attributeMatch, err := regexp.Compile(arnRegexp)

		if err != nil {
			return fmt.Errorf("Unable to compile ARN regexp (%s): %w", arnRegexp, err)
		}

		return resource.TestMatchResourceAttr(resourceName, attributeName, attributeMatch)(s)
	}
}

// testAccMatchResourceAttrGlobalARNNoAccount ensures the Terraform state regexp matches a formatted ARN without region or account ID
func testAccMatchResourceAttrGlobalARNNoAccount(resourceName, attributeName, arnService string, arnResourceRegexp *regexp.Regexp) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		arnRegexp := arn.ARN{
			Partition: testAccGetPartition(),
			Resource:  arnResourceRegexp.String(),
			Service:   arnService,
		}.String()

		attributeMatch, err := regexp.Compile(arnRegexp)

		if err != nil {
			return fmt.Errorf("Unable to compile ARN regexp (%s): %s", arnRegexp, err)
		}

		return resource.TestMatchResourceAttr(resourceName, attributeName, attributeMatch)(s)
	}
}

// testAccCheckResourceAttrRfc3339 ensures the Terraform state matches a RFC3339 value
// This TestCheckFunc will likely be moved to the Terraform Plugin SDK in the future.
func testAccCheckResourceAttrRfc3339(resourceName, attributeName string) resource.TestCheckFunc {
	return resource.TestMatchResourceAttr(resourceName, attributeName, regexp.MustCompile(rfc3339RegexPattern))
}

// testAccCheckListHasSomeElementAttrPair is a TestCheckFunc which validates that the collection on the left has an element with an attribute value
// matching the value on the left
// Based on TestCheckResourceAttrPair from the Terraform SDK testing framework
func testAccCheckListHasSomeElementAttrPair(nameFirst string, resourceAttr string, elementAttr string, nameSecond string, keySecond string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		isFirst, err := primaryInstanceState(s, nameFirst)
		if err != nil {
			return err
		}

		isSecond, err := primaryInstanceState(s, nameSecond)
		if err != nil {
			return err
		}

		vSecond, ok := isSecond.Attributes[keySecond]
		if !ok {
			return fmt.Errorf("%s: No attribute %q found", nameSecond, keySecond)
		} else if vSecond == "" {
			return fmt.Errorf("%s: No value was set on attribute %q", nameSecond, keySecond)
		}

		attrsFirst := make([]string, 0, len(isFirst.Attributes))
		attrMatcher := regexp.MustCompile(fmt.Sprintf("%s\\.\\d+\\.%s", resourceAttr, elementAttr))
		for k := range isFirst.Attributes {
			if attrMatcher.MatchString(k) {
				attrsFirst = append(attrsFirst, k)
			}
		}

		found := false
		for _, attrName := range attrsFirst {
			vFirst := isFirst.Attributes[attrName]
			if vFirst == vSecond {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: No element of %q found with attribute %q matching value %q set on %q of %s", nameFirst, resourceAttr, elementAttr, vSecond, keySecond, nameSecond)
		}

		return nil
	}
}

// testAccCheckResourceAttrEquivalentJSON is a TestCheckFunc that compares a JSON value with an expected value. Both JSON
// values are normalized before being compared.
func testAccCheckResourceAttrEquivalentJSON(resourceName, attributeName, expectedJSON string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		is, err := primaryInstanceState(s, resourceName)
		if err != nil {
			return err
		}

		v, ok := is.Attributes[attributeName]
		if !ok {
			return fmt.Errorf("%s: No attribute %q found", resourceName, attributeName)
		}

		vNormal, err := structure.NormalizeJsonString(v)
		if err != nil {
			return fmt.Errorf("%s: Error normalizing JSON in %q: %w", resourceName, attributeName, err)
		}

		expectedNormal, err := structure.NormalizeJsonString(expectedJSON)
		if err != nil {
			return fmt.Errorf("Error normalizing expected JSON: %w", err)
		}

		if vNormal != expectedNormal {
			return fmt.Errorf("%s: Attribute %q expected\n%s\ngot\n%s", resourceName, attributeName, expectedJSON, v)
		}
		return nil
	}
}

// Copied and inlined from the SDK testing code
func primaryInstanceState(s *terraform.State, name string) (*terraform.InstanceState, error) {
	rs, ok := s.RootModule().Resources[name]
	if !ok {
		return nil, fmt.Errorf("Not found: %s", name)
	}

	is := rs.Primary
	if is == nil {
		return nil, fmt.Errorf("No primary instance: %s", name)
	}

	return is, nil
}

// testAccGetAccountID returns the account ID of testAccProvider
// Must be used within a resource.TestCheckFunc
func testAccGetAccountID() string {
	return testAccWafruleProviderAccountID(testAccProvider)
}

func testAccGetRegion() string {
	return envvar.GetWithDefault(envvar.AwsDefaultRegion, endpoints.UsWest2RegionID)
}

func testAccGetAlternateRegion() string {
	return envvar.GetWithDefault(envvar.AwsAlternateRegion, endpoints.UsEast1RegionID)
}

func testAccGetThirdRegion() string {
	return envvar.GetWithDefault(envvar.AwsThirdRegion, endpoints.UsEast2RegionID)
}

func testAccGetPartition() string {
	if partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), testAccGetRegion()); ok {
		return partition.ID()
	}
	return "aws"
}

func testAccGetPartitionDNSSuffix() string {
	if partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), testAccGetRegion()); ok {
		return partition.DNSSuffix()
	}
	return "amazonaws.com"
}

func testAccGetPartitionReverseDNSPrefix() string {
	if partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), testAccGetRegion()); ok {
		return ReverseDns(partition.DNSSuffix())
	}

	return "com.amazonaws"
}

func testAccGetAlternateRegionPartition() string {
	if partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), testAccGetAlternateRegion()); ok {
		return partition.ID()
	}
	return "aws"
}

func testAccGetThirdRegionPartition() string {
	if partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), testAccGetThirdRegion()); ok {
		return partition.ID()
	}
	return "aws"
}

func testAccAlternateAccountPreCheck(t *testing.T) {
	envvar.TestFailIfAllEmpty(t, []string{envvar.AwsAlternateProfile, envvar.AwsAlternateAccessKeyId}, "credentials for running acceptance testing in alternate AWS account")

	if os.Getenv(envvar.AwsAlternateAccessKeyId) != "" {
		envvar.TestFailIfEmpty(t, envvar.AwsAlternateSecretAccessKey, "static credentials value when using "+envvar.AwsAlternateAccessKeyId)
	}
}

func testAccPartitionHasServicePreCheck(serviceId string, t *testing.T) {
	if partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), testAccGetRegion()); ok {
		if _, ok := partition.Services()[serviceId]; !ok {
			t.Skip(fmt.Sprintf("skipping tests; partition %s does not support %s service", partition.ID(), serviceId))
		}
	}
}

func testAccMultipleRegionPreCheck(t *testing.T, regions int) {
	if testAccGetRegion() == testAccGetAlternateRegion() {
		t.Fatalf("%s and %s must be set to different values for acceptance tests", envvar.AwsDefaultRegion, envvar.AwsAlternateRegion)
	}

	if testAccGetPartition() != testAccGetAlternateRegionPartition() {
		t.Fatalf("%s partition (%s) does not match %s partition (%s)", envvar.AwsAlternateRegion, testAccGetAlternateRegionPartition(), envvar.AwsDefaultRegion, testAccGetPartition())
	}

	if regions >= 3 {
		if testAccGetRegion() == testAccGetThirdRegion() {
			t.Fatalf("%s and %s must be set to different values for acceptance tests", envvar.AwsDefaultRegion, envvar.AwsThirdRegion)
		}

		if testAccGetAlternateRegion() == testAccGetThirdRegion() {
			t.Fatalf("%s and %s must be set to different values for acceptance tests", envvar.AwsAlternateRegion, envvar.AwsThirdRegion)
		}

		if testAccGetPartition() != testAccGetThirdRegionPartition() {
			t.Fatalf("%s partition (%s) does not match %s partition (%s)", envvar.AwsThirdRegion, testAccGetThirdRegionPartition(), envvar.AwsDefaultRegion, testAccGetPartition())
		}
	}

	if partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), testAccGetRegion()); ok {
		if len(partition.Regions()) < regions {
			t.Skipf("skipping tests; partition includes %d regions, %d expected", len(partition.Regions()), regions)
		}
	}
}

// testAccRegionPreCheck checks that the test region is the specified region.
func testAccRegionPreCheck(t *testing.T, region string) {
	if testAccGetRegion() != region {
		t.Skipf("skipping tests; %s (%s) does not equal %s", envvar.AwsDefaultRegion, testAccGetRegion(), region)
	}
}

// testAccPartitionPreCheck checks that the test partition is the specified partition.
func testAccPartitionPreCheck(partition string, t *testing.T) {
	if testAccGetPartition() != partition {
		t.Skipf("skipping tests; current partition (%s) does not equal %s", testAccGetPartition(), partition)
	}
}

func testAccAlternateAccountProviderConfig() string {
	//lintignore:AT004
	return fmt.Sprintf(`
provider "awsalternate" {
  access_key = %[1]q
  profile    = %[2]q
  secret_key = %[3]q
}
`, os.Getenv(envvar.AwsAlternateAccessKeyId), os.Getenv(envvar.AwsAlternateProfile), os.Getenv(envvar.AwsAlternateSecretAccessKey))
}

func testAccAlternateAccountAlternateRegionProviderConfig() string {
	//lintignore:AT004
	return fmt.Sprintf(`
provider "awsalternate" {
  access_key = %[1]q
  profile    = %[2]q
  region     = %[3]q
  secret_key = %[4]q
}
`, os.Getenv(envvar.AwsAlternateAccessKeyId), os.Getenv(envvar.AwsAlternateProfile), testAccGetAlternateRegion(), os.Getenv(envvar.AwsAlternateSecretAccessKey))
}

// When testing needs to distinguish a second region and second account in the same region
// e.g. cross-region functionality with RAM shared subnets
func testAccAlternateAccountAndAlternateRegionProviderConfig() string {
	//lintignore:AT004
	return fmt.Sprintf(`
provider "awsalternateaccountalternateregion" {
  access_key = %[1]q
  profile    = %[2]q
  region     = %[3]q
  secret_key = %[4]q
}

provider "awsalternateaccountsameregion" {
  access_key = %[1]q
  profile    = %[2]q
  secret_key = %[4]q
}

provider "awssameaccountalternateregion" {
  region = %[3]q
}
`, os.Getenv(envvar.AwsAlternateAccessKeyId), os.Getenv(envvar.AwsAlternateProfile), testAccGetAlternateRegion(), os.Getenv(envvar.AwsAlternateSecretAccessKey))
}

// Deprecated: Use testAccMultipleRegionProviderConfig instead
func testAccAlternateRegionProviderConfig() string {
	return testAccNamedRegionalProviderConfig(ProviderNameWafruleAlternate, testAccGetAlternateRegion())
}

func testAccMultipleRegionProviderConfig(regions int) string {
	var config strings.Builder

	config.WriteString(testAccNamedRegionalProviderConfig(ProviderNameWafruleAlternate, testAccGetAlternateRegion()))

	if regions >= 3 {
		config.WriteString(testAccNamedRegionalProviderConfig(ProviderNameWafruleThird, testAccGetThirdRegion()))
	}

	return config.String()
}

// testAccNamedRegionalProviderConfig creates a new provider named configuration with a region.
//
// This can be used to build multiple provider configuration testing.
func testAccNamedRegionalProviderConfig(providerName string, region string) string {
	//lintignore:AT004
	return fmt.Sprintf(`
provider %[1]q {
  region = %[2]q
}
`, providerName, region)
}

// testAccRegionalProviderConfig creates a new provider configuration with a region.
//
// This can only be used for single provider configuration testing as it
// overwrites the "wafrule" provider configuration.
func testAccRegionalProviderConfig(region string) string {
	//lintignore:AT004
	return fmt.Sprintf(`
provider "wafrule" {
  region = %[1]q
}
`, region)
}

func testAccAwsRegionProviderFunc(region string, providers *[]*schema.Provider) func() *schema.Provider {
	return func() *schema.Provider {
		if region == "" {
			log.Println("[DEBUG] No region given")
			return nil
		}
		if providers == nil {
			log.Println("[DEBUG] No providers given")
			return nil
		}

		log.Printf("[DEBUG] Checking providers for AWS region: %s", region)
		for _, provider := range *providers {
			// Ignore if Meta is empty, this can happen for validation providers
			if provider == nil || provider.Meta() == nil {
				log.Printf("[DEBUG] Skipping empty provider")
				continue
			}

			// Ignore if Meta is not AWSClient, this will happen for other providers
			client, ok := provider.Meta().(*AWSClient)
			if !ok {
				log.Printf("[DEBUG] Skipping non-AWS provider")
				continue
			}

			clientRegion := client.region
			log.Printf("[DEBUG] Checking AWS provider region %q against %q", clientRegion, region)
			if clientRegion == region {
				log.Printf("[DEBUG] Found AWS provider with region: %s", region)
				return provider
			}
		}

		log.Printf("[DEBUG] No suitable provider found for %q in %d providers", region, len(*providers))
		return nil
	}
}

func testAccDeleteResource(resource *schema.Resource, d *schema.ResourceData, meta interface{}) error {
	if resource.DeleteContext != nil || resource.DeleteWithoutTimeout != nil {
		var diags diag.Diagnostics

		if resource.DeleteContext != nil {
			diags = resource.DeleteContext(context.Background(), d, meta)
		} else {
			diags = resource.DeleteWithoutTimeout(context.Background(), d, meta)
		}

		for i := range diags {
			if diags[i].Severity == diag.Error {
				return fmt.Errorf("error deleting resource: %s", diags[i].Summary)
			}
		}

		return nil
	}

	return resource.Delete(d, meta)
}

func testAccCheckResourceDisappears(provider *schema.Provider, resource *schema.Resource, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState, ok := s.RootModule().Resources[resourceName]

		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		if resourceState.Primary.ID == "" {
			return fmt.Errorf("resource ID missing: %s", resourceName)
		}

		return testAccDeleteResource(resource, resource.Data(resourceState.Primary), provider.Meta())
	}
}

func testAccCheckWithProviders(f func(*terraform.State, *schema.Provider) error, providers *[]*schema.Provider) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		numberOfProviders := len(*providers)
		for i, provider := range *providers {
			if provider.Meta() == nil {
				log.Printf("[DEBUG] Skipping empty provider %d (total: %d)", i, numberOfProviders)
				continue
			}
			log.Printf("[DEBUG] Calling check with provider %d (total: %d)", i, numberOfProviders)
			if err := f(s, provider); err != nil {
				return err
			}
		}
		return nil
	}
}

// testAccErrorCheckSkipMessagesContaining skips tests based on error messages that indicate unsupported features
func testAccErrorCheckSkipMessagesContaining(t *testing.T, messages ...string) resource.ErrorCheckFunc {
	return func(err error) error {
		if err == nil {
			return nil
		}

		for _, message := range messages {
			errorMessage := err.Error()
			if strings.Contains(errorMessage, message) {
				t.Skipf("skipping test for %s/%s: %s", testAccGetPartition(), testAccGetRegion(), errorMessage)
			}
		}

		return err
	}
}

type ServiceErrorCheckFunc func(*testing.T) resource.ErrorCheckFunc

var serviceErrorCheckFuncs map[string]ServiceErrorCheckFunc

func RegisterServiceErrorCheckFunc(endpointID string, f ServiceErrorCheckFunc) {
	if serviceErrorCheckFuncs == nil {
		serviceErrorCheckFuncs = make(map[string]ServiceErrorCheckFunc)
	}

	if _, ok := serviceErrorCheckFuncs[endpointID]; ok {
		// already registered
		panic(fmt.Sprintf("Cannot re-register a service! ServiceErrorCheckFunc exists for %s", endpointID)) //lintignore:R009
	}

	serviceErrorCheckFuncs[endpointID] = f
}

func testAccErrorCheck(t *testing.T, endpointIDs ...string) resource.ErrorCheckFunc {
	return func(err error) error {
		if err == nil {
			return nil
		}

		for _, endpointID := range endpointIDs {
			if f, ok := serviceErrorCheckFuncs[endpointID]; ok {
				ef := f(t)
				err = ef(err)
			}

			if err == nil {
				break
			}
		}

		if testAccErrorCheckCommon(err) {
			t.Skipf("skipping test for %s/%s: %s", testAccGetPartition(), testAccGetRegion(), err.Error())
		}

		return err
	}
}

// NOTE: This function cannot use the standard tfawserr helpers
// as it is receiving error strings from the SDK testing framework,
// not actual error types from the resource logic.
func testAccErrorCheckCommon(err error) bool {
	if strings.Contains(err.Error(), "is not supported in this") {
		return true
	}

	if strings.Contains(err.Error(), "is currently not supported") {
		return true
	}

	if strings.Contains(err.Error(), "InvalidAction") {
		return true
	}

	if strings.Contains(err.Error(), "Unknown operation") {
		return true
	}

	if strings.Contains(err.Error(), "UnknownOperationException") {
		return true
	}

	if strings.Contains(err.Error(), "UnsupportedOperation") {
		return true
	}

	return false
}

// Check service API call error for reasons to skip acceptance testing
// These include missing API endpoints and unsupported API calls
func testAccPreCheckSkipError(err error) bool {
	// GovCloud has endpoints that respond with (no message provided after the error code):
	// AccessDeniedException:
	// Ignore these API endpoints that exist but are not officially enabled
	if isAWSErr(err, "AccessDeniedException", "") {
		return true
	}
	// Ignore missing API endpoints
	if isAWSErr(err, "RequestError", "send request failed") {
		return true
	}
	// Ignore unsupported API calls
	if isAWSErr(err, "UnknownOperationException", "") {
		return true
	}
	if isAWSErr(err, "UnsupportedOperation", "") {
		return true
	}
	if isAWSErr(err, "InvalidInputException", "Unknown operation") {
		return true
	}
	if isAWSErr(err, "InvalidAction", "is not valid") {
		return true
	}
	if isAWSErr(err, "InvalidAction", "Unavailable Operation") {
		return true
	}
	return false
}

func TestAccWafruleProvider_Region_AwsC2S(t *testing.T) {
	var providers []*schema.Provider

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ErrorCheck:        testAccErrorCheck(t),
		ProviderFactories: testAccProviderFactoriesInternal(&providers),
		CheckDestroy:      nil,
		Steps: []resource.TestStep{
			{
				Config: testAccWafruleProviderConfigRegion("us-iso-east-1"), // lintignore:AWSAT003
				Check: resource.ComposeTestCheckFunc(
					testAccCheckWafruleProviderDnsSuffix(&providers, "c2s.ic.gov"),
					testAccCheckWafruleProviderPartition(&providers, "aws-iso"),
					testAccCheckWafruleProviderReverseDnsPrefix(&providers, "gov.ic.c2s"),
				),
				PlanOnly: true,
			},
		},
	})
}

func TestAccWafruleProvider_Region_AwsChina(t *testing.T) {
	var providers []*schema.Provider

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ErrorCheck:        testAccErrorCheck(t),
		ProviderFactories: testAccProviderFactoriesInternal(&providers),
		CheckDestroy:      nil,
		Steps: []resource.TestStep{
			{
				Config: testAccWafruleProviderConfigRegion("cn-northwest-1"), // lintignore:AWSAT003
				Check: resource.ComposeTestCheckFunc(
					testAccCheckWafruleProviderDnsSuffix(&providers, "amazonaws.com.cn"),
					testAccCheckWafruleProviderPartition(&providers, "aws-cn"),
					testAccCheckWafruleProviderReverseDnsPrefix(&providers, "cn.com.amazonaws"),
				),
				PlanOnly: true,
			},
		},
	})
}

func TestAccWafruleProvider_Region_AwsCommercial(t *testing.T) {
	var providers []*schema.Provider

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ErrorCheck:        testAccErrorCheck(t),
		ProviderFactories: testAccProviderFactoriesInternal(&providers),
		CheckDestroy:      nil,
		Steps: []resource.TestStep{
			{
				Config: testAccWafruleProviderConfigRegion("us-west-2"), // lintignore:AWSAT003
				Check: resource.ComposeTestCheckFunc(
					testAccCheckWafruleProviderDnsSuffix(&providers, "amazonaws.com"),
					testAccCheckWafruleProviderPartition(&providers, "aws"),
					testAccCheckWafruleProviderReverseDnsPrefix(&providers, "com.amazonaws"),
				),
				PlanOnly: true,
			},
		},
	})
}

func TestAccWafruleProvider_Region_AwsGovCloudUs(t *testing.T) {
	var providers []*schema.Provider

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ErrorCheck:        testAccErrorCheck(t),
		ProviderFactories: testAccProviderFactoriesInternal(&providers),
		CheckDestroy:      nil,
		Steps: []resource.TestStep{
			{
				Config: testAccWafruleProviderConfigRegion("us-gov-west-1"), // lintignore:AWSAT003
				Check: resource.ComposeTestCheckFunc(
					testAccCheckWafruleProviderDnsSuffix(&providers, "amazonaws.com"),
					testAccCheckWafruleProviderPartition(&providers, "aws-us-gov"),
					testAccCheckWafruleProviderReverseDnsPrefix(&providers, "com.amazonaws"),
				),
				PlanOnly: true,
			},
		},
	})
}

func TestAccWafruleProvider_Region_AwsSC2S(t *testing.T) {
	var providers []*schema.Provider

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ErrorCheck:        testAccErrorCheck(t),
		ProviderFactories: testAccProviderFactoriesInternal(&providers),
		CheckDestroy:      nil,
		Steps: []resource.TestStep{
			{
				Config: testAccWafruleProviderConfigRegion("us-isob-east-1"), // lintignore:AWSAT003
				Check: resource.ComposeTestCheckFunc(
					testAccCheckWafruleProviderDnsSuffix(&providers, "sc2s.sgov.gov"),
					testAccCheckWafruleProviderPartition(&providers, "aws-iso-b"),
					testAccCheckWafruleProviderReverseDnsPrefix(&providers, "gov.sgov.sc2s"),
				),
				PlanOnly: true,
			},
		},
	})
}

func testAccCheckWafruleProviderDnsSuffix(providers *[]*schema.Provider, expectedDnsSuffix string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if providers == nil {
			return fmt.Errorf("no providers initialized")
		}

		for _, provider := range *providers {
			if provider == nil || provider.Meta() == nil || provider.Meta().(*AWSClient) == nil {
				continue
			}

			providerDnsSuffix := provider.Meta().(*AWSClient).dnsSuffix

			if providerDnsSuffix != expectedDnsSuffix {
				return fmt.Errorf("expected DNS Suffix (%s), got: %s", expectedDnsSuffix, providerDnsSuffix)
			}
		}

		return nil
	}
}

func testAccCheckWafruleProviderPartition(providers *[]*schema.Provider, expectedPartition string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if providers == nil {
			return fmt.Errorf("no providers initialized")
		}

		for _, provider := range *providers {
			if provider == nil || provider.Meta() == nil || provider.Meta().(*AWSClient) == nil {
				continue
			}

			providerPartition := provider.Meta().(*AWSClient).partition

			if providerPartition != expectedPartition {
				return fmt.Errorf("expected DNS Suffix (%s), got: %s", expectedPartition, providerPartition)
			}
		}

		return nil
	}
}

func testAccCheckWafruleProviderReverseDnsPrefix(providers *[]*schema.Provider, expectedReverseDnsPrefix string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if providers == nil {
			return fmt.Errorf("no providers initialized")
		}

		for _, provider := range *providers {
			if provider == nil || provider.Meta() == nil || provider.Meta().(*AWSClient) == nil {
				continue
			}

			providerReverseDnsPrefix := provider.Meta().(*AWSClient).reverseDnsPrefix

			if providerReverseDnsPrefix != expectedReverseDnsPrefix {
				return fmt.Errorf("expected DNS Suffix (%s), got: %s", expectedReverseDnsPrefix, providerReverseDnsPrefix)
			}
		}

		return nil
	}
}

func testAccWafruleProviderConfigEndpoints(endpoints string) string {
	//lintignore:AT004
	return fmt.Sprintf(`
provider "wafrule" {
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    %[1]s
  }
}
`, endpoints)
}

func testAccAssumeRoleARNPreCheck(t *testing.T) {
	envvar.TestSkipIfEmpty(t, envvar.TfAccAssumeRoleArn, "Amazon Resource Name (ARN) of existing IAM Role to assume for testing restricted permissions")
}

func testAccProviderConfigAssumeRolePolicy(policy string) string {
	//lintignore:AT004
	return fmt.Sprintf(`
provider "wafrule" {
  assume_role {
    role_arn = %q
    policy   = %q
  }
}
`, os.Getenv(envvar.TfAccAssumeRoleArn), policy)
}

const testAccCheckWafruleProviderConfigAssumeRoleEmpty = `
provider "wafrule" {
  assume_role {
  }
}
` //lintignore:AT004

func testCheckResourceAttrIsSortedCsv(resourceName, attributeName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		is, err := primaryInstanceState(s, resourceName)
		if err != nil {
			return err
		}

		v, ok := is.Attributes[attributeName]
		if !ok {
			return fmt.Errorf("%s: No attribute %q found", resourceName, attributeName)
		}

		splitV := strings.Split(v, ",")
		if !sort.StringsAreSorted(splitV) {
			return fmt.Errorf("%s: Expected attribute %q to be sorted, got %q", resourceName, attributeName, v)
		}

		return nil
	}
}

// composeConfig can be called to concatenate multiple strings to build test configurations
func composeConfig(config ...string) string {
	var str strings.Builder

	for _, conf := range config {
		str.WriteString(conf)
	}

	return str.String()
}
