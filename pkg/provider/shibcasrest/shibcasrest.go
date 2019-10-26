package shibcasrest

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "shibboleth")

// Client wrapper around Shibboleth enabling authentication and retrieval of assertions
type Client struct {
	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

// New create a new Shibboleth client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
	}

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client:     client,
		idpAccount: idpAccount,
	}, nil
}

// Authenticate authenticate to Shibboleth via CAS REST and return the data from the body of the SAML assertion.
func (sc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var samlAssertion string

	// Make a HTTP GET to the Shibboleth IDP. We do this for two reasons:
	// 1. Need to establish a session for the later callback w/ CAS service ticket
	// 2. Need to determine the CAS url from the final redirect
	shibbolethURL := fmt.Sprintf("%s/idp/profile/SAML2/Unsolicited/SSO?providerId=%s", loginDetails.URL, sc.idpAccount.AmazonWebservicesURN)
	idpResp, err := sc.client.Get(shibbolethURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "Error contacting Shibboleth IDP")
	}

	// The HTTP GET above should have triggered several redirects, the last of which is to CAS
	// Get the CAS URL from this final request
	casURL := idpResp.Request.URL
	casURLBase := fmt.Sprintf("%s://%s", casURL.Scheme, casURL.Host)

	// Obtain a Ticket Granting Ticket (TGT) from CAS for the username/password
	tgt, err := getTGT(casURLBase, loginDetails)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "Could not get a TGT from CAS")
	}

	// Get the CAS Service
	casService := casURL.Query().Get("service")

	// We'll also need the `conversation` param from the service later on, so let's get it now
	re := regexp.MustCompile(`\?conversation=(e\d{1,}s\d{1,})`)
	shibConversation := re.FindStringSubmatch(casService)

	st, err := getST(tgt, casService)
	fmt.Println(st)
	// Make a call back to the IDP with the Service Ticket
	shibCallbackURL := fmt.Sprintf("%s/idp/Authn/ExtCas?conversation=%s,entityId=%s,ticket=%s", loginDetails.URL, shibConversation, sc.idpAccount.AmazonWebservicesURN, st)
	idpCallbackResp, err := sc.client.Get(shibCallbackURL)
	if err != nil {
		return "", errors.Wrap(err, "Error calling back to Shibboleth with Service Ticket")
	}

	// extract the SAML response from the response body
	samlAssertion, err = extractSamlResponse(idpCallbackResp)

	if err != nil {
		return samlAssertion, errors.Wrap(err, "error extracting SAMLResponse blob from final Shibboleth response")
	}

	return samlAssertion, nil

}

func getTGT(casURLBase string, user *creds.LoginDetails) (string, error) {
	casRestURL := fmt.Sprintf("%s/cas/v1/tickets", casURLBase)
	resp, err := http.PostForm(casRestURL, url.Values{"username": {user.Username}, "password": {user.Password}})
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()
	location, err := resp.Location()
	if err != nil {
		return "", errors.Wrap(err, "Error retreiving a TGT from CAS")
	}

	return location.String(), nil
}

func getST(tgt string, service string) (string, error) {
	resp, err := http.PostForm(tgt, url.Values{"service": {service}})
	if err != nil {
		return "", errors.Wrap(err, "Error getting ST from CAS")
	}

	defer resp.Body.Close()
	st, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "Error parsing response body")
	}

	return string(st), nil
}

// copied from ../shibboleth.go
func extractSamlResponse(res *http.Response) (string, error) {
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(body))
	samlRgx := regexp.MustCompile(`name=\"SAMLResponse\" value=\"(.*?)\"/>`)
	samlResponseValue := samlRgx.FindStringSubmatch(string(body))
	return samlResponseValue[1], nil
}
