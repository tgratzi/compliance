package com.tzachi.common;

import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;
import org.apache.http.entity.StringEntity;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.apache.http.HttpEntity;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.json.simple.parser.ParseException;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;


public class HttpHelper {
    private String host;
    private String password;
    private String username;

    public HttpHelper(String host, String password, String username) {
//        Logger.getLogger("org.apache.http").setLevel(Level.INFO);
        this.password = password;
        this.username = username;
        this.host = host;
    }

    private CloseableHttpClient getHttpsClient() {
        TrustStrategy TRUST_ALL_TRUST_STRATEGY = new TrustSelfSignedStrategy() {
            public boolean isTrusted(java.security.cert.X509Certificate[] chain, String authType)
                    throws java.security.cert.CertificateException {
                return true;
            }
        };

        SSLConnectionSocketFactory sslsf;
        try {
            SSLContext sslContext = SSLContexts.custom().
                    useProtocol("TLSv1.2")
                    .loadTrustMaterial(null, TRUST_ALL_TRUST_STRATEGY)
                    .build();
            sslsf = new SSLConnectionSocketFactory(
                    sslContext,
                    new String[] { "TLSv1.2" },
                    null,
                    SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        } catch (GeneralSecurityException e) {
            // NOTE: the assumption is that this error should not happen
            throw new RuntimeException("Failed to create SSL socket factory", e);
        }

        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(
                new AuthScope(host, 443),
                new UsernamePasswordCredentials(username, password));
        CloseableHttpClient httpclient = HttpClients.custom()
                .setSSLSocketFactory(sslsf)
                .setDefaultCredentialsProvider(credsProvider)
                .build();
        return httpclient;
    }

    public JSONObject post(String uri, String str) throws IOException {
        System.out.println("Running post request");
        String url = MessageFormat.format(uri, host);
        CloseableHttpClient httpclient = getHttpsClient();
        CloseableHttpResponse response = null;
        JSONObject returnData = new JSONObject();
        HttpPost httppost = new HttpPost(url);
        httppost.addHeader("content-type", "application/xml");
        try {
            httppost.setEntity(new StringEntity(str));
            System.out.println("Executing request " + httppost.getRequestLine());
            response = httpclient.execute(httppost);
//            System.out.println(response.getEntity());
            int status = response.getStatusLine().getStatusCode();
            if (status >= 200 && status < 300) {
                returnData = getJsonFromHttpResponse(response);
            } else {
                String msg = "HTTP status: " + status + ", \nResponse: " + EntityUtils.toString(response.getEntity());
                throw new IOException(msg);
            }
        } finally {
            if (null != response) {
                response.close();
                httpclient.close();
            }
        }
        return returnData;
    }

    public JSONObject get(String uri) throws ParseException {
        CloseableHttpClient httpclient = getHttpsClient();
        String url = MessageFormat.format(uri, host);
        HttpGet get = new HttpGet(url);
        CloseableHttpResponse response = null;
        JSONObject returnData = new JSONObject();
        try {
            response = httpclient.execute(get);
            int status = response.getStatusLine().getStatusCode();
            if (status >= 200 && status < 300) {
                returnData = getJsonFromHttpResponse(response);
            } else {
                System.out.println("Unexpected response status: " + status);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(null != response){
                try {
                    response.close();
                    httpclient.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return returnData;
    }

    private JSONObject getJsonFromHttpResponse(CloseableHttpResponse response) throws IOException {
        JSONParser parser = new JSONParser();
        JSONObject returnData = new JSONObject();
        HttpEntity entity = response.getEntity();
        if (entity == null) {
            returnData.put("status_code", "1");
            returnData.put("error_message", "null Data Found");
        } else {
            String jsonString = EntityUtils.toString(entity, "UTF-8");
            try {
                returnData = (JSONObject) parser.parse(jsonString);
            } catch (ParseException ex) {
                throw new IOException(ex.getMessage());
            }
        }
        return returnData;
    }
}

