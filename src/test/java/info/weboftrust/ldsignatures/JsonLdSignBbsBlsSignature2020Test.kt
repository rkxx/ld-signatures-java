package info.weboftrust.ldsignatures

import bbs.signatures.Bbs
import bbs.signatures.KeyPair
import com.google.crypto.tink.subtle.Hex
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import foundation.identity.jsonld.JsonLDUtils
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords
import info.weboftrust.ldsignatures.signer.BbsBlsSignature2020LdSigner
import info.weboftrust.ldsignatures.signer.BbsBlsSignatureProof2020LdProofer
import info.weboftrust.ldsignatures.verifier.BbsBlsSignature2020LdVerifier
import info.weboftrust.ldsignatures.verifier.BbsBlsSignatureProof2020LdVerifier
import io.ipfs.multibase.Base58
import org.junit.jupiter.api.Test
import java.net.URI
import java.util.*
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

fun ByteArray.toBls12381G2DidKey(): String {
    require(Bbs.getBls12381G2PublicKeySize() == this.size)
    return "did:key:z${Base58.encode(byteArrayOf(0xeb.toByte(), 0x01) + this)}"
}

fun String.toBls12381G2PublicKey(): ByteArray {
    require(this.lowercase().startsWith("did:key:"))
    require(this.substring(8..10) == "zUC")
    val byteArray = Base58.decode(this.drop(9))
    require(byteArray.size == Bbs.getBls12381G2PublicKeySize() + 2)
    require(byteArray.copyOfRange(0, 2).contentEquals(byteArrayOf(0xeb.toByte(), 0x01)))
    return byteArray.copyOfRange(2, byteArray.size)
}

class JsonLdSignBbsBlsSignature2020Test {

    val didKeyIssuer =
        "did:key:zUC78bhyjquwftxL92uP5xdUA7D7rtNQ43LZjvymncP2KTXtQud1g9JH4LYqoXZ6fyiuDJ2PdkNU9j6cuK1dsGjFB2tEMvTnnHP7iZJomBmmY1xsxBqbPsCMtH6YmjP4ocfGLwv"
    val verkeyIssuer =
        "tmA6gAFiKH67j6EXv1wFrorCcc4C24ndsYPxJkvDaaB61JfNyUu8FtbAeYCr9gBG55cWbLWemqYexSHWi1PXM5MWZaZgpeFdSucQry8u44q1bHVzJw2FiUgaJYeBE4WPrLc"
    val keyPairIssuer = KeyPair(
        Hex.decode("9642f47f8f970fe5a36f67d74841cf0885141ccc8eae92685b4dbda5891b42ab132ab0b8c8df8ec11316bdddddbed330179ca7dc7c6dbbd7bf74584831087bb9884d504a76afd4d8f03c14c1e6acccb7bf76b4e2068725456f65fca1bdc184b5"),
        Hex.decode("4b72cad121e0459dce3c5ead7683e82185459a77ac33a9bcd84423c36683acf5")
    )

    val didKeyHolder =
        "did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V"
    val verkeyHolder =
        "xr2pBCj7voA6TX7QGf1WwvjgHtSsg4NfP7qf9b1ZsAjBqZiR9Xkwg3qsTEeDYujXbnt2J5E5Jj58hkc1c415PUAtBmwtdGxVj6X7cTvVDBobMke8XbihHeMyueQDCxKotUB"
    val keyPairHolder = KeyPair(
        Hex.decode("a21e0d512342b0b6ebf0d86ab3a2cef2a57bab0c0eeff0ffebad724107c9f33d69368531b41b1caa5728730f52aea54817b087f0d773cb1a753f1ede255468e88cea6665c6ce1591c88b079b0c4f77d0967d8211b1bc8687213e2af041ba73c4"),
        Hex.decode("4318a7863ecbf9b347f3bd892828c588c20e61e5fa7344b7268643adb5a2bd4e")
    )

    init {
        (JsonLDObject.DEFAULT_DOCUMENT_LOADER as ConfigurableDocumentLoader).apply {
            isEnableHttps = true
        }
    }

    @Test
    fun testDidExtensions() {
        val keyPair = Bbs.generateBls12381G2Key(Random.nextBytes(32))
        val didKey = keyPair.publicKey.toBls12381G2DidKey()
        val publicKey = didKey.toBls12381G2PublicKey()
        assert(keyPair.publicKey.contentEquals(publicKey))
//        println("secretKey: ${Hex.encode(keyPair.secretKey)}")
//        println("publicKey: ${Hex.encode(keyPair.publicKey)}")
//        println("did: $didKey")
//        println("verKey: ${Base58.encode(keyPair.publicKey)}")
    }

    @Test
    fun testSignerKeys() {
        assert(didKeyIssuer.toBls12381G2PublicKey().contentEquals(keyPairIssuer.publicKey))
        assert(Base58.decode(verkeyIssuer).contentEquals(keyPairIssuer.publicKey))
    }

    @Test
    fun testHolderKeys() {
        assert(didKeyHolder.toBls12381G2PublicKey().contentEquals(keyPairHolder.publicKey))
        assert(Base58.decode(verkeyHolder).contentEquals(keyPairHolder.publicKey))
    }

    @Test
    fun signJsonLDObject() {
        val jsonLDObject = JsonLDObject.fromJson(javaClass.getResource("SimpleJsonLDObject.jsonld")?.readText())

        // sign credential (assertion proof)
        val ldProof = BbsBlsSignature2020LdSigner(keyPairIssuer).apply {
            created = Date(1678115674126)
            proofPurpose = LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD
            verificationMethod = URI.create("${didKeyIssuer}#${didKeyIssuer.drop(8)}")
        }.sign(jsonLDObject)

        // assert correctness of signed document
        LdProof.removeLdProofValues(LdProof.getFromJsonLDObject(jsonLDObject))
        val expectedNormalizedDoc = """
                _:c14n0 <http://purl.org/dc/terms/created> "2023-03-06T15:14:34Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n2 .
                _:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> _:c14n2 .
                _:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n2 .
                _:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC78bhyjquwftxL92uP5xdUA7D7rtNQ43LZjvymncP2KTXtQud1g9JH4LYqoXZ6fyiuDJ2PdkNU9j6cuK1dsGjFB2tEMvTnnHP7iZJomBmmY1xsxBqbPsCMtH6YmjP4ocfGLwv#zUC78bhyjquwftxL92uP5xdUA7D7rtNQ43LZjvymncP2KTXtQud1g9JH4LYqoXZ6fyiuDJ2PdkNU9j6cuK1dsGjFB2tEMvTnnHP7iZJomBmmY1xsxBqbPsCMtH6YmjP4ocfGLwv> _:c14n2 .
                _:c14n1 <http://schema.org/familyName> "Smith" .
                _:c14n1 <http://schema.org/gender> "Male" .
                _:c14n1 <http://schema.org/givenName> "John" .
                _:c14n1 <https://w3id.org/security#proof> _:c14n2 .

            """.trimIndent()
        assertEquals(expectedNormalizedDoc, jsonLDObject.normalize(null))
        // IOP test: jsonLDObject was exported to and verified by jsonld-signatures-bbs
    }

    @Test
    fun verifyJsonLDObject() {
        // IOP test: SimpleJsonLDObjectWithBbsProof.jsonld was created by jsonld-signatures-bbs
        val jsonLDObject =
            JsonLDObject.fromJson(javaClass.getResource("SimpleJsonLDObjectWithBbsProof.jsonld")?.readText())
        val verificationResult = BbsBlsSignature2020LdVerifier(keyPairIssuer.publicKey).verify(jsonLDObject)
        assertTrue(verificationResult, "unsuccessful verification")
    }

    @Test
    fun createCredential() {
        val issuanceDate = "2028-02-21T09:50:45Z"
        val expirationDate = "2033-02-21T09:50:45Z"
        // create credential
        val credentialJsonLdObject = JsonLDObject.builder()
            .contexts(
                listOf(
                    URI("https://www.w3.org/2018/credentials/v1"),
                    URI("https://w3id.org/vaccination/v1"),
                )
            )
            .types(listOf("VerifiableCredential", "VaccinationCertificate"))
            .properties(
                mapOf(
                    "name" to "COVID-19 Vaccination Certificate",
                    "description" to "COVID-19 Vaccination Certificate",
                    "issuanceDate" to issuanceDate,
                    "expirationDate" to expirationDate,
                    "issuer" to didKeyIssuer,
                    "credentialSubject" to mapOf(
                        "type" to "VaccinationEvent",
                        "batchNumber" to "1183738569",
                        "administeringCentre" to "MoH",
                        "healthProfessional" to "MoH",
                        "countryOfVaccination" to "NZ",
                        "recipient" to mapOf(
                            "id" to didKeyHolder,
                            "type" to "VaccineRecipient",
                            "givenName" to "JOHN",
                            "familyName" to "SMITH",
                            "gender" to "Male",
                            "birthDate" to "1958-07-17"
                        ),
                        "vaccine" to mapOf(
                            "type" to "Vaccine",
                            "disease" to "COVID-19",
                            "atcCode" to "J07BX03",
                            "medicinalProductName" to "COVID-19 Vaccine Moderna",
                            "marketingAuthorizationHolder" to "Moderna Biotech"
                        )
                    )
                )
            )
            .build()

        // sign credential (assertion proof)
        val verificationMethod = "${didKeyIssuer}#${didKeyIssuer.drop(8)}"
        BbsBlsSignature2020LdSigner(keyPairIssuer).apply {
            created = JsonLDUtils.DATE_FORMAT.parse(issuanceDate)
            proofPurpose = LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD
            this.verificationMethod = URI.create(verificationMethod)
        }.sign(credentialJsonLdObject)

        // assert correctness of signed document
        LdProof.removeLdProofValues(LdProof.getFromJsonLDObject(credentialJsonLdObject))
        val expectedNormalizedDoc = """
            <did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
            <did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V> <http://schema.org/familyName> "SMITH" .
            <did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V> <http://schema.org/gender> "Male" .
            <did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V> <http://schema.org/givenName> "JOHN" .
            <did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#VaccineRecipient> .
            _:c14n1 <http://purl.org/dc/terms/created> "2028-02-21T09:50:45Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
            _:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> _:c14n0 .
            _:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
            _:c14n1 <https://w3id.org/security#verificationMethod> <did:key:zUC78bhyjquwftxL92uP5xdUA7D7rtNQ43LZjvymncP2KTXtQud1g9JH4LYqoXZ6fyiuDJ2PdkNU9j6cuK1dsGjFB2tEMvTnnHP7iZJomBmmY1xsxBqbPsCMtH6YmjP4ocfGLwv#zUC78bhyjquwftxL92uP5xdUA7D7rtNQ43LZjvymncP2KTXtQud1g9JH4LYqoXZ6fyiuDJ2PdkNU9j6cuK1dsGjFB2tEMvTnnHP7iZJomBmmY1xsxBqbPsCMtH6YmjP4ocfGLwv> _:c14n0 .
            _:c14n2 <http://schema.org/description> "COVID-19 Vaccination Certificate" .
            _:c14n2 <http://schema.org/name> "COVID-19 Vaccination Certificate" .
            _:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#VaccinationCertificate> .
            _:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
            _:c14n2 <https://w3id.org/security#proof> _:c14n0 .
            _:c14n2 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n3 .
            _:c14n2 <https://www.w3.org/2018/credentials#expirationDate> "2033-02-21T09:50:45Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
            _:c14n2 <https://www.w3.org/2018/credentials#issuanceDate> "2028-02-21T09:50:45Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
            _:c14n2 <https://www.w3.org/2018/credentials#issuer> <did:key:zUC78bhyjquwftxL92uP5xdUA7D7rtNQ43LZjvymncP2KTXtQud1g9JH4LYqoXZ6fyiuDJ2PdkNU9j6cuK1dsGjFB2tEMvTnnHP7iZJomBmmY1xsxBqbPsCMtH6YmjP4ocfGLwv> .
            _:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#VaccinationEvent> .
            _:c14n3 <https://w3id.org/vaccination#VaccineEventVaccine> _:c14n4 .
            _:c14n3 <https://w3id.org/vaccination#administeringCentre> "MoH" .
            _:c14n3 <https://w3id.org/vaccination#batchNumber> "1183738569" .
            _:c14n3 <https://w3id.org/vaccination#countryOfVaccination> "NZ" .
            _:c14n3 <https://w3id.org/vaccination#healthProfessional> "MoH" .
            _:c14n3 <https://w3id.org/vaccination#recipient> <did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V> .
            _:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#Vaccine> .
            _:c14n4 <https://w3id.org/vaccination#atc-code> "J07BX03" .
            _:c14n4 <https://w3id.org/vaccination#disease> "COVID-19" .
            _:c14n4 <https://w3id.org/vaccination#marketingAuthorizationHolder> "Moderna Biotech" .
            _:c14n4 <https://w3id.org/vaccination#medicinalProductName> "COVID-19 Vaccine Moderna" .

        """.trimIndent()
        assertEquals(expectedNormalizedDoc, credentialJsonLdObject.normalize(null))
        // IOP test: credentialJsonObject was exported to and verified by jsonld-signatures-bbs
    }

    @Test
    fun verifyCredential() {
        // IOP test: VaccinationCredentialWithBbsProof.jsonld was created by jsonld-signatures-bbs
        val credentialJsonLdObject =
            JsonLDObject.fromJson(javaClass.getResource("VaccinationCredentialWithBbsProof.jsonld")?.readText())
        val verificationResult = BbsBlsSignature2020LdVerifier(keyPairIssuer.publicKey).verify(credentialJsonLdObject)
        assertTrue(verificationResult, "unsuccessful verification")
    }

    @Test
    fun createPresentation() {
        val issuanceDate = "2028-02-21T09:50:45Z"
        val expirationDate = "2033-02-21T09:50:45Z"

        // take existing credential, frame it and derive proof
        val nonce = "/du/xAnXQvMFg/WV7ggvWBaWWbmJhFhc+VFh7K1W+0NwwoA9co6NoOBfjGYz9cFkL24="
        val challenge = "challenge"

        val credentialJsonLdObject =
            JsonLDObject.fromJson(javaClass.getResource("VaccinationCredentialWithBbsProof.jsonld")?.readText())
        val frameJsonLdObject =
            JsonLDObject.fromJson(javaClass.getResource("VaccinationCredentialFrameDoc.jsonld")?.readText())
        val framedJsonLdObject =
            BbsBlsSignatureProof2020LdProofer(keyPairIssuer.publicKey, Base64.getDecoder().decode(nonce)).deriveProof(
                credentialJsonLdObject,
                frameJsonLdObject
            )

        val presentation = JsonLDObject.builder()
            .contexts(
                listOf(
                    URI("https://www.w3.org/2018/credentials/v1"),
                    URI("https://identity.foundation/presentation-exchange/submission/v1"),
                )
            )
            .types(listOf("VerifiablePresentation", "PresentationSubmission"))
            .properties(
                mapOf(
                    "presentation_submission" to mapOf(
                        "definition_id" to "32f54163-7166-48f1-93d8-ff217bdb0653",
                        "descriptor_map" to listOf(
                            mapOf(
                                "format" to "ldp_vc",
                                "path" to "$.verifiableCredential[0]"
                            )
                        ),
                    ),
                    "verifiableCredential" to listOf(
                        framedJsonLdObject.toMap()
                    )
                )
            )
            .build()

        // sign presentation (authentication proof)
        val verificationMethod = "${didKeyHolder}#${didKeyHolder.drop(8)}"
        BbsBlsSignature2020LdSigner(keyPairHolder).apply {
            created = JsonLDUtils.DATE_FORMAT.parse(issuanceDate)
            proofPurpose = LDSecurityKeywords.JSONLD_TERM_AUTHENTICATION
            this.challenge = challenge
            this.verificationMethod = URI.create(verificationMethod)
        }.sign(presentation)

        // assert correctness of presentation
        LdProof.removeLdProofValues(LdProof.getFromJsonLDObject(presentation))
        val assertionProof = LdProof.fromJsonObject(((presentation.jsonObject.get("verifiableCredential") as List<*>).get(0) as Map<*,*>).get("proof") as Map<String, Object>)
        LdProof.removeLdProofValues(assertionProof)
        val expectedNormalizedDoc = """
                <$didKeyHolder> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#VaccineRecipient> _:c14n3 .
                <urn:bnid:_:c14n0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#VaccinationEvent> _:c14n3 .
                <urn:bnid:_:c14n0> <https://w3id.org/vaccination#administeringCentre> "MoH" _:c14n3 .
                <urn:bnid:_:c14n0> <https://w3id.org/vaccination#batchNumber> "1183738569" _:c14n3 .
                <urn:bnid:_:c14n0> <https://w3id.org/vaccination#countryOfVaccination> "NZ" _:c14n3 .
                <urn:bnid:_:c14n0> <https://w3id.org/vaccination#recipient> <$didKeyHolder> _:c14n3 .
                <urn:bnid:_:c14n2> <http://schema.org/description> "COVID-19 Vaccination Certificate" _:c14n3 .
                <urn:bnid:_:c14n2> <http://schema.org/name> "COVID-19 Vaccination Certificate" _:c14n3 .
                <urn:bnid:_:c14n2> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#VaccinationCertificate> _:c14n3 .
                <urn:bnid:_:c14n2> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n3 .
                <urn:bnid:_:c14n2> <https://w3id.org/security#proof> _:c14n5 _:c14n3 .
                <urn:bnid:_:c14n2> <https://www.w3.org/2018/credentials#credentialSubject> <urn:bnid:_:c14n0> _:c14n3 .
                <urn:bnid:_:c14n2> <https://www.w3.org/2018/credentials#expirationDate> "2033-02-21T09:50:45Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n3 .
                <urn:bnid:_:c14n2> <https://www.w3.org/2018/credentials#issuanceDate> "2028-02-21T09:50:45Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n3 .
                <urn:bnid:_:c14n2> <https://www.w3.org/2018/credentials#issuer> <$didKeyIssuer> _:c14n3 .
                _:c14n1 <http://purl.org/dc/terms/created> "2023-03-15T14:45:57Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n5 .
                _:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignatureProof2020> _:c14n5 .
                _:c14n1 <https://w3id.org/security#nonce> "/du/xAnXQvMFg/WV7ggvWBaWWbmJhFhc+VFh7K1W+0NwwoA9co6NoOBfjGYz9cFkL24=" _:c14n5 .
                _:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n5 .
                _:c14n1 <https://w3id.org/security#verificationMethod> <$didKeyIssuer#${didKeyIssuer.substring(8)}> _:c14n5 .
                _:c14n2 <http://purl.org/dc/terms/created> "2028-02-21T09:50:45Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
                _:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> _:c14n0 .
                _:c14n2 <https://w3id.org/security#challenge> "challenge" _:c14n0 .
                _:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#authenticationMethod> _:c14n0 .
                _:c14n2 <https://w3id.org/security#verificationMethod> <$didKeyHolder#${didKeyHolder.substring(8)}> _:c14n0 .
                _:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://identity.foundation/presentation-exchange/#presentation-submission> .
                _:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
                _:c14n4 <https://identity.foundation/presentation-exchange/#presentation-submission> "{\"definition_id\":\"32f54163-7166-48f1-93d8-ff217bdb0653\",\"descriptor_map\":[{\"format\":\"ldp_vc\",\"path\":\"${'$'}.verifiableCredential[0]\"}]}"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .
                _:c14n4 <https://w3id.org/security#proof> _:c14n0 .
                _:c14n4 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n3 .

        """.trimIndent()

        assertEquals(expectedNormalizedDoc, presentation.normalize(null))
    }

    @Test
    fun verifyPresentation() {
        val presentationJsonLdObject =
            JsonLDObject.fromJson(javaClass.getResource("VaccinationPresentation.jsonld")?.readText())
        val credential =
            presentationJsonLdObject.toJsonObject().getJsonArray("verifiableCredential").get(0).asJsonObject()
        var verificationResult = BbsBlsSignatureProof2020LdVerifier(keyPairIssuer.publicKey).apply {
            proofPurpose = LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD
        }.verifyProof(JsonLDObject.fromJson(credential.toString()))
        assertTrue(verificationResult, "unsuccessful assertion proof verification")
        verificationResult = BbsBlsSignature2020LdVerifier(keyPairHolder.publicKey).apply {
            proofPurpose = LDSecurityKeywords.JSONLD_TERM_AUTHENTICATION
        }.verify(presentationJsonLdObject)
        assertTrue(verificationResult, "unsuccessful authentication (holder binding)")
    }
}