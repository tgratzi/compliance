package com.tzachi.lib.helpers;


import org.apache.http.entity.StringEntity;
import org.apache.http.ssl.SSLContextBuilder;
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
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.simple.parser.ParseException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import java.io.IOException;
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

    private SSLConnectionSocketFactory getSSLSocketFactory() throws IOException {
        SSLConnectionSocketFactory sslsf;
        try {
            SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
            sslContextBuilder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
            HostnameVerifier hostnameVerifierAllowAll = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
            sslsf = new SSLConnectionSocketFactory(sslContextBuilder.build(), hostnameVerifierAllowAll);
        } catch (Exception ex) {
            throw new IOException("Failed to set SSL socket");
        }
        return sslsf;
    }

    private CloseableHttpClient getHttpsClient() {
        try {
            CredentialsProvider credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(
                    new AuthScope(host, 443),
                    new UsernamePasswordCredentials(username, password));
            CloseableHttpClient httpclient = HttpClients.custom()
                    .setSSLSocketFactory(getSSLSocketFactory())
                    .setDefaultCredentialsProvider(credsProvider)
                    .build();
            return httpclient;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return HttpClients.custom().build();
    }

    public JSONObject post(String uri, String body, String contentType) throws IOException {
        String url = MessageFormat.format(uri, host);
        CloseableHttpClient httpclient = getHttpsClient();
        CloseableHttpResponse response = null;
        JSONObject returnData = new JSONObject();
        HttpPost httppost = new HttpPost(url);
        httppost.addHeader("content-type", contentType);
        try {
            httppost.setEntity(new StringEntity(body));
            System.out.println("Executing request " + httppost.getRequestLine());
            response = httpclient.execute(httppost);
//            System.out.println("response: " + response.getEntity());
            int status = response.getStatusLine().getStatusCode();
            if (status >= 200 && status < 300) {
                returnData = getJsonFromHttpResponse(response);
            } else {
                String msg = "HTTP status: " + status + ", \nResponse: " + EntityUtils.toString(response.getEntity());
                throw new IOException(msg);
            }
        } catch (Exception ex) {
            throw new IOException(ex.getMessage());
        } finally {
            if (null != response) {
                response.close();
                httpclient.close();
            }
        }
        return returnData;
    }

    public JSONObject get(String uri) throws IOException {
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
                String msg = "HTTP status: " + status + ", \nResponse: " + EntityUtils.toString(response.getEntity());
                throw new IOException(msg);
            }
        } catch (Exception ex) {
            throw new IOException(ex.getMessage());
        } finally {
            if(null != response) {
                response.close();
                httpclient.close();
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

