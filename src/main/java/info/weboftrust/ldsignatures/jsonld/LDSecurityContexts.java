package info.weboftrust.ldsignatures.jsonld;

import com.apicatalog.jsonld.api.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.loader.DocumentLoader;
import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDObject;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class LDSecurityContexts {

    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_V1 = URI.create("https://w3id.org/security/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_V2 = URI.create("https://w3id.org/security/v2");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_V3 = URI.create("https://w3id.org/security/v3");

    public static final Map<URI, JsonDocument> CONTEXTS;
    public static final DocumentLoader DOCUMENT_LOADER;

    static {

        try {

            CONTEXTS = new HashMap<>();

            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_V1,
                    JsonDocument.of(MediaType.JSON_LD, LDSecurityContexts.class.getResourceAsStream("security-v1.jsonld")));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_V2,
                    JsonDocument.of(MediaType.JSON_LD, LDSecurityContexts.class.getResourceAsStream("security-v2.jsonld")));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_V3,
                    JsonDocument.of(MediaType.JSON_LD, LDSecurityContexts.class.getResourceAsStream("security-v3-unstable.jsonld")));

            for (Map.Entry<URI, JsonDocument> context : CONTEXTS.entrySet()) {
                context.getValue().setDocumentUrl(context.getKey());
            }
        } catch (JsonLdError ex) {

            throw new ExceptionInInitializerError(ex);
        }

        DOCUMENT_LOADER = new ConfigurableDocumentLoader(CONTEXTS);
    }
}
