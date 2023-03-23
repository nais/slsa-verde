package attestation

import (
	"context"
	"cuelang.org/go/pkg/strings"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/in-toto/in-toto-golang/in_toto"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"picante/internal/identity"
	"picante/internal/pod"
)

type ImageMetadata struct {
	BundleVerified bool                        `json:"bundleVerified"`
	Image          string                      `json:"image"`
	Statement      *in_toto.CycloneDXStatement `json:"statement"`
}

type VerifyAttestationOpts struct {
	Issuer    string
	ProjectID string
	VerifyCmd *verify.VerifyAttestationCommand
	Logger    *log.Entry
}

//func (vao *VerifyAttestationOpts) options(ctx context.Context, team string) (*cosign.CheckOpts, error) {
//	co := &cosign.CheckOpts{
//		IgnoreTlog: vao.VerifyCmd.IgnoreTlog,
//		IgnoreSCT:  vao.VerifyCmd.IgnoreSCT,
//	}
//
//	var err error
//	if !co.IgnoreSCT {
//		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
//		if err != nil {
//			return nil, fmt.Errorf("getting ctlog public keys: %w", err)
//		}
//	}
//
//	if !co.IgnoreTlog {
//		if vao.VerifyCmd.RekorURL != "" {
//			rekorClient, err := rekor.NewClient(vao.VerifyCmd.RekorURL)
//			if err != nil {
//				return nil, fmt.Errorf("creating Rekor client: %w", err)
//			}
//			co.RekorClient = rekorClient
//		}
//		// This performs an online fetch of the Rekor public keys, but this is needed
//		// for verifying tlog entries (both online and offline).
//		co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
//		if err != nil {
//			return nil, fmt.Errorf("getting Rekor public keys: %w", err)
//		}
//	}
//
//	if keylessVerification(vao.VerifyCmd.KeyRef) {
//		log.Debugf("Using keyless verification")
//		// This performs an online fetch of the Fulcio roots. This is needed
//		// for verifying keyless certificates (both online and offline).
//		co.RootCerts, err = fulcio.GetRoots()
//		if err != nil {
//			return nil, fmt.Errorf("getting Fulcio roots: %w", err)
//		}
//		co.IntermediateCerts, err = fulcio.GetIntermediates()
//		if err != nil {
//			return nil, fmt.Errorf("getting Fulcio intermediates: %w", err)
//		}
//
//		co.Identities = identity.GetIdentities(vao.ProjectID, vao.Issuer, team)
//	}
//
//	if vao.VerifyCmd.KeyRef != "" {
//		co.SigVerifier, err = sigs.PublicKeyFromKeyRef(ctx, vao.VerifyCmd.KeyRef)
//		if err != nil {
//			return nil, fmt.Errorf("loading public key: %w", err)
//		}
//		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
//		if ok {
//			defer pkcs11Key.Close()
//		}
//		co.IgnoreTlog = vao.VerifyCmd.IgnoreTlog
//	}
//
//	return co, nil
//}

func keylessVerification(keyRef string) bool {
	if keyRef != "" {
		return false
	}
	return true
}

func (vao *VerifyAttestationOpts) WithOptions(pod *pod.Info) {
	if keylessVerification(vao.VerifyCmd.KeyRef) {
		vao.Logger.Info("Using keyless verification setting up identity")
		vao.VerifyCmd.CertIdentityRegexp = identity.ToSubject(vao.ProjectID, "")
		vao.VerifyCmd.CertOidcIssuer = vao.Issuer
	}
	vao.VerifyCmd.PredicateType = pod.PredicateType
}

func (vao *VerifyAttestationOpts) runCosign(ctx context.Context, image string) ([]byte, error) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := vao.VerifyCmd.Exec(ctx, []string{image})
	if err != nil {
		fmt.Println("Error: ", err)
	}

	w.Close()
	outData, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout
	if !strings.HasPrefix(string(outData), "{") {
		return nil, fmt.Errorf("parse cosign out data: %v", err)
	}
	return outData, nil
}

func (vao *VerifyAttestationOpts) Verify(ctx context.Context, pod *pod.Info) ([]*ImageMetadata, error) {
	metadata := make([]*ImageMetadata, 0)
	for _, image := range pod.ContainerImages {
		vao.Logger.WithFields(log.Fields{
			"image": image,
		})

		vao.WithOptions(pod)

		vao.Logger.WithFields(log.Fields{
			"pod":   pod.Name,
			"image": image,
		}).Infof("verifying image attestations")

		outData, err := vao.runCosign(ctx, image)
		if err != nil {
			return nil, fmt.Errorf("run cosign: %v", err)
		}

		vao.Logger.Debug("parsing Cosign output")
		statement, err := parseEnvelope(outData)
		if err != nil {
			return nil, fmt.Errorf("parse envelope: %v", err)
		}

		vao.Logger.WithFields(log.Fields{
			"predicate-type": statement.PredicateType,
			"statement-type": statement.Type,
			"ref":            image,
		}).Info("attestation verified and parsed statement")

		metadata = append(metadata, &ImageMetadata{
			Statement:      statement,
			Image:          image,
			BundleVerified: true,
		})
	}
	return metadata, nil
}

//func (vao *VerifyAttestationOpts) Verify(ctx context.Context, pod *pod.Info) ([]*ImageMetadata, error) {
//
//	metadata := make([]*ImageMetadata, 0)
//
//	vaoVerify2(ctx, pod)
//
//	for _, image := range pod.ContainerImages {
//		ref, err := name.ParseReference(image)
//		if err != nil {
//			return nil, fmt.Errorf("parse reference: %v", err)
//		}
//
//		opts, err := vao.options(ctx, pod.Team)
//		if err != nil {
//			return nil, fmt.Errorf("get options: %v", err)
//		}
//
//		var verified []oci.Signature
//		var bVerified bool
//		var statement *in_toto.CycloneDXStatement
//
//		if vao.VerifyCmd.LocalImage {
//			verified, bVerified, err = cosign.VerifyLocalImageAttestations(ctx, image, opts)
//			if err != nil {
//				return nil, err
//			}
//		} else {
//			verified, bVerified, err = cosign.VerifyImageAttestations(ctx, ref, opts)
//			if err != nil {
//				return nil, err
//			}
//		}
//
//		att := verified[len(verified)-1]
//
//		env, err := att.Payload()
//		if err != nil {
//			return nil, fmt.Errorf("get payload: %v", err)
//		}
//		statement, err = parseEnvelope(env)
//		if err != nil {
//			return nil, fmt.Errorf("parse payload: %v", err)
//		}
//
//		log.Infof("attestation statement verified and parsed: %v: ref %s", statement.PredicateType, ref)
//
//		metadata = append(metadata, &ImageMetadata{
//			Statement:      statement,
//			Image:          ref.String(),
//			BundleVerified: bVerified,
//		})
//	}
//	return metadata, nil
//}

func parseEnvelope(dsseEnvelope []byte) (*in_toto.CycloneDXStatement, error) {
	var env = ssldsse.Envelope{}
	err := json.Unmarshal(dsseEnvelope, &env)
	if err != nil {
		return nil, err
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	var stat = &in_toto.CycloneDXStatement{}
	err = json.Unmarshal(decodedPayload, &stat)
	if err != nil {
		return nil, err
	}
	return stat, nil
}
