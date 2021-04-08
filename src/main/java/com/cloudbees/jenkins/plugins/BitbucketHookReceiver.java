package com.cloudbees.jenkins.plugins;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;

import java.io.IOException;
import java.net.URLDecoder;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import net.sf.json.JSONObject;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.kohsuke.stapler.StaplerRequest;

/**
 * @author <a href="mailto:nicolas.deloof@gmail.com">Nicolas De Loof</a>
 */
@Extension
public class BitbucketHookReceiver implements UnprotectedRootAction {

    private final BitbucketPayloadProcessor payloadProcessor = new BitbucketPayloadProcessor();
    public static final String BITBUCKET_HOOK_URL = "bitbucket-hook";

    public String getIconFileName() {
        return null;
    }

    public String getDisplayName() {
        return null;
    }

    public String getUrlName() {
        return BITBUCKET_HOOK_URL;
    }

    /**
     * Bitbucket send <a href="https://confluence.atlassian.com/display/BITBUCKET/Write+brokers+(hooks)+for+Bitbucket">payload</a>
     * as form-urlencoded <pre>payload=JSON</pre>
     * @throws IOException
     */
    public void doIndex(StaplerRequest req) throws IOException {
        String body = IOUtils.toString(req.getInputStream());
        if (!body.isEmpty() && req.getRequestURI().contains("/" + BITBUCKET_HOOK_URL + "/")) {
            String contentType = req.getContentType();
            if (contentType != null && contentType.startsWith("application/json")) {
                String key = "SECERT_KEY";
                String signature = req.getHeader("X-Hub-Signature");
                if (signature != null) {
                    signature = signature.substring(7);
                    try {
                        HMac hmac = new HMac(new SHA256Digest());
                        hmac.init(new KeyParameter(key.getBytes()));
                        byte[] result = new byte[hmac.getMacSize()];
                        byte[] bytes = body.getBytes();
                        hmac.update(bytes, 0, bytes.length);
                        hmac.doFinal(result, 0);
                        String hash = Hex.encodeHexString(result);
                        LOGGER.log(Level.INFO, "SHA256HMAC Computed: {0}", hash);
                        if (hash.equals(signature)) {
                            LOGGER.log(Level.INFO, "SHA256HMAC Computed verifies the X-Hub-Signature header");
                        } else {
                            LOGGER.log(Level.INFO, "SHA256HMAC Computed does not match the X-Hub-Signature header! Skip processing of webhook!");
                            return;
                        }
                    }
                    catch (Exception e){
                        LOGGER.log(Level.INFO, "Unable to compute SHA256HMAC for signature validation.");
                    }
                }
            }
            if (body.startsWith("payload=")) body = body.substring(8);

            LOGGER.log(Level.FINE, "Received commit hook notification : {0}", body);
            JSONObject payload = JSONObject.fromObject(body);

            payloadProcessor.processPayload(payload, req);
        } else {
            LOGGER.log(Level.WARNING, "The Jenkins job cannot be triggered. You might not have configured correctly the WebHook on BitBucket with the last slash `http://<JENKINS-URL>/bitbucket-hook/` or a 'Test connection' invocation of the hook was triggered.");
        }

    }

    private static final Logger LOGGER = Logger.getLogger(BitbucketHookReceiver.class.getName());
}
