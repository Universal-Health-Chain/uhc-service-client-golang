/* Copyright 2021 Fundación UNID */
package models

const DidDocSchema = `
{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",

    "dc": "http://purl.org/dc/terms/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "schema": "http://schema.org/",
    "sec": "https://w3id.org/security#",
    "didv": "https://w3id.org/did#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "AuthenticationSuite": "sec:AuthenticationSuite",
    "CryptographicKey": "sec:Key",
    "EquihashProof2017": "sec:EquihashProof2017",
    "GraphSignature2012": "sec:GraphSignature2012",
    "IssueCredential": "didv:IssueCredential",
    "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
    "LinkedDataSignature2016": "sec:LinkedDataSignature2016",
    "RsaCryptographicKey": "sec:RsaCryptographicKey",
    "RsaSignatureAuthentication2018": "sec:RsaSignatureAuthentication2018",
    "RsaSigningKey2018": "sec:RsaSigningKey",
    "RsaSignature2015": "sec:RsaSignature2015",
    "RsaSignature2017": "sec:RsaSignature2017",
    "UpdateDidDescription": "didv:UpdateDidDescription",

    "authentication": "sec:authenticationMethod",
    "authenticationCredential": "sec:authenticationCredential",
    "authorizationCapability": "sec:authorizationCapability",
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "capability": "sec:capability",
    "comment": "rdfs:comment",
    "created": {"@id": "dc:created", "@type": "xsd:dateTime"},
    "creator": {"@id": "dc:creator", "@type": "@id"},
    "description": "schema:description",
    "digestAlgorithm": "sec:digestAlgorithm",
    "digestValue": "sec:digestValue",
    "domain": "sec:domain",
    "entity": "sec:entity",
    "equihashParameterAlgorithm": "sec:equihashParameterAlgorithm",
    "equihashParameterK": {"@id": "sec:equihashParameterK", "@type": "xsd:integer"},
    "equihashParameterN": {"@id": "sec:equihashParameterN", "@type": "xsd:integer"},
    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "field": {"@id": "didv:field", "@type": "@id"},
    "label": "rdfs:label",
    "minimumProofsRequired": "sec:minimumProofsRequired",
    "minimumSignaturesRequired": "sec:minimumSignaturesRequired",
    "name": "schema:name",
    "nonce": "sec:nonce",
    "normalizationAlgorithm": "sec:normalizationAlgorithm",
    "owner": {"@id": "sec:owner", "@type": "@id"},
    "permission": "sec:permission",
    "permittedProofType": "sec:permittedProofType",
    "privateKey": {"@id": "sec:privateKey", "@type": "@id"},
    "privateKeyPem": "sec:privateKeyPem",
    "proof": "sec:proof",
    "proofAlgorithm": "sec:proofAlgorithm",
    "proofType": "sec:proofType",
    "proofValue": "sec:proofValue",
    "publicKey": {"@id": "sec:publicKey", "@type": "@id", "@container": "@set"},
    "publicKeyPem": "sec:publicKeyPem",
    "requiredProof": "sec:requiredProof",
    "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
    "seeAlso": {"@id": "rdfs:seeAlso", "@type": "@id"},
    "signature": "sec:signature",
    "signatureAlgorithm": "sec:signatureAlgorithm",
    "signatureValue": "sec:signatureValue"
  }
}`