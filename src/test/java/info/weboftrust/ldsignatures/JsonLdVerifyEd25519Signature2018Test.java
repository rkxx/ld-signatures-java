package info.weboftrust.ldsignatures;

import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.crypto.provider.Ed25519Provider;
import info.weboftrust.ldsignatures.crypto.provider.RandomProvider;
import info.weboftrust.ldsignatures.crypto.provider.SHA256Provider;
import info.weboftrust.ldsignatures.crypto.provider.impl.JavaRandomProvider;
import info.weboftrust.ldsignatures.crypto.provider.impl.JavaSHA256Provider;
import info.weboftrust.ldsignatures.crypto.provider.impl.TinkEd25519Provider;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdVerifyEd25519Signature2018Test {

	@BeforeEach
	public void before() {

		RandomProvider.set(new JavaRandomProvider());
		SHA256Provider.set(new JavaSHA256Provider());
		Ed25519Provider.set(new TinkEd25519Provider());
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdVerifyEd25519Signature2018Test.class.getResourceAsStream("signed.good.ed25519.jsonld")));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(TestUtil.testEd25519PublicKey);
		boolean verify = verifier.verify(jsonLdObject);
		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdVerifyEd25519Signature2018Test.class.getResourceAsStream("signed.bad.ed25519.jsonld")));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(TestUtil.testEd25519PublicKey);
		boolean verify = verifier.verify(jsonLdObject);
		assertFalse(verify);
	}
}
