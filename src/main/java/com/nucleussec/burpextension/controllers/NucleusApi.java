/*
 * Copyright (c) 2020 Nucleus Security - All Rights Reserved
 */
package com.nucleussec.burpextension.controllers;

import com.nucleussec.burpextension.view.MainView;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.prefs.Preferences;
import javax.swing.JOptionPane;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class NucleusApi {
    
    private OkHttpClient client;
    private MainView mainView;
    private Preferences prefs;
    
    public NucleusApi(MainView mainView, Preferences prefs) {
        this.client = new OkHttpClient();
        this.mainView = mainView;
        this.prefs = prefs;
    }
        
    public void uploadScanFile(File scanFile, String scanFileName) throws IOException, NullPointerException {
        RequestBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("scan_description", "Uploaded via Nucleus Burp Extension")
                .addFormDataPart(scanFileName, scanFile.getName(),
                        RequestBody.create(scanFile, MediaType.parse("application/xml")))
                .build();
        mainView.setProgressBar(60);
        Request request = new Request.Builder().url(mainView.getInstanceUrl() + "nucleus/api/projects/" + mainView.getCurrentSelectedProject() + "/scans")
                .addHeader("x-apikey", prefs.get("x-apikey", "")).post(requestBody).build();
        mainView.setProgressBar(75);
        Response response = client.newCall(request).execute();
        if(response.code() != 200) {
            JOptionPane.showMessageDialog(mainView, "An error has occured uploading the scan. Error code: " + response.code(), "Error has occured", JOptionPane.ERROR_MESSAGE);
            mainView.setProgressBar(0);
        } else mainView.setProgressBar(90);
    }
    
    public HashMap<String, String> getProjects() throws IOException, JSONException {
        HashMap<String, String> projects = new HashMap<>();
        Request request = new Request.Builder()
                .url(mainView.getInstanceUrl() + "nucleus/api/projects")
                .addHeader("x-apikey", prefs.get("x-apikey", ""))
                .build();
        Response response = client.newCall(request).execute();
        
        JSONArray jsonArray = new JSONArray(response.body().string());
        jsonArray.forEach(o -> {
            JSONObject jsonObj = (JSONObject) o;
            projects.put(jsonObj.getString("project_id"), jsonObj.getString("project_name"));
        });
        return projects;
    }
}
