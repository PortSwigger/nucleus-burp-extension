/*
 * Copyright (c) 2020 Nucleus Security - All Rights Reserved
 */
package com.nucleussec.burpextension.view;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import com.nucleussec.burpextension.controllers.NucleusApi;
import com.nucleussec.burpextension.utils.GlobalUtils;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Timer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;

public class MainView extends javax.swing.JPanel {
    
    private IBurpExtenderCallbacks callbacks;
    private Preferences prefs;
    private NucleusApi nucleusApi;
    
    /**
     * Creates new form MainView
     */
    public MainView(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.prefs = Preferences.userRoot().node(this.getClass().getName());
        this.nucleusApi = new NucleusApi(this, prefs);
        initComponents();
        
        String instanceUrl = prefs.get("instance_url", "");
        txtNucleusInstanceURL.setText(instanceUrl);
        
        String apiKey = prefs.get("x-apikey", "");
        if(!apiKey.isEmpty()) {
            pwApiKey.setText(apiKey);
        }
        
        if(!apiKey.isEmpty() && !instanceUrl.isEmpty()) {
            populateProjectsComboBox();
        }
    }
    
    private void populateProjectsComboBox() {
        cbProjects.removeAllItems();
        try {
            nucleusApi.getProjects().forEach((projectId, projectName) -> {
                cbProjects.addItem(projectId + " - " + projectName);
            });
        } catch (IOException ex) {
            Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public String getCurrentSelectedProject() {
        String selectedItem = (String) cbProjects.getSelectedItem();
        return selectedItem.split("-")[0].replaceAll(" ", "");
    }
    
    public String getInstanceUrl() {
        String url = txtNucleusInstanceURL.getText();
        if(!url.contains("://"))
            url = "http://" + url;
        if(!url.substring(url.length()-1).equals("/"))
            url = url + "/";
        return url;
    }
    
    public void setProgressBar(int n) {
        jProgressBar.setValue(n);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        cbProjects = new javax.swing.JComboBox<>();
        btnPushToNucleus = new javax.swing.JButton();
        jProgressBar = new javax.swing.JProgressBar();
        jLabel4 = new javax.swing.JLabel();
        btnSyncWithNucleus = new javax.swing.JButton();
        pwApiKey = new javax.swing.JPasswordField();
        jLabel5 = new javax.swing.JLabel();
        txtNucleusInstanceURL = new javax.swing.JTextField();

        jPanel1.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("Nucleus Security Burp Extension");

        jLabel2.setText("Nucleus API Key:");

        jLabel3.setText("Project:");

        btnPushToNucleus.setText("Push All Scan Issues to Nucleus");
        btnPushToNucleus.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnPushToNucleusActionPerformed(evt);
            }
        });

        jLabel4.setText("Scan Upload Status");

        btnSyncWithNucleus.setText("Sync with Nucleus");
        btnSyncWithNucleus.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSyncWithNucleusActionPerformed(evt);
            }
        });

        pwApiKey.setText("jPasswordField1");

        jLabel5.setText("Nucleus Instance URL:");

        txtNucleusInstanceURL.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtNucleusInstanceURLKeyReleased(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnPushToNucleus)
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(cbProjects, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(pwApiKey, javax.swing.GroupLayout.PREFERRED_SIZE, 188, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnSyncWithNucleus))
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel4)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jProgressBar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(txtNucleusInstanceURL)))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(txtNucleusInstanceURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 14, Short.MAX_VALUE)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(btnSyncWithNucleus)
                    .addComponent(pwApiKey, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(cbProjects, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(15, 15, 15)
                        .addComponent(jLabel4))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnPushToNucleus)
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(276, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(158, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void btnPushToNucleusActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnPushToNucleusActionPerformed
        long currentTime = System.currentTimeMillis();
        String fileName = System.getenv("USERPROFILE")+"\\AppData\\Local\\Temp\\nucleusBurpExtension-" + currentTime + ".xml";
        IScanIssue[] scanIssues = callbacks.getScanIssues("");
        File file = new File(fileName);
        setProgressBar(15);
        new Thread(new Runnable() {
            @Override
            public void run() {
                callbacks.generateScanReport("xml", scanIssues, file);
                jProgressBar.setValue(30);
                while(!GlobalUtils.isCompletelyWritten(file)) {
                    try {
                        Thread.sleep(1000);
                        jProgressBar.setValue(45);
                    } catch (InterruptedException ex) {
                        Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
        
                try {
                    nucleusApi.uploadScanFile(file, file.getName());
                    jProgressBar.setValue(100);
                } catch (IOException ex) {
                    System.out.println(ex.getMessage());
                }
            }
        }).start();        
    }//GEN-LAST:event_btnPushToNucleusActionPerformed

    private void btnSyncWithNucleusActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSyncWithNucleusActionPerformed
        char[] apiKey = pwApiKey.getPassword();
        if(apiKey.length > 0) {
            prefs.put("x-apikey", String.valueOf(apiKey));
            populateProjectsComboBox();
        }
    }//GEN-LAST:event_btnSyncWithNucleusActionPerformed

    private void txtNucleusInstanceURLKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtNucleusInstanceURLKeyReleased
        prefs.put("instance_url", txtNucleusInstanceURL.getText());
    }//GEN-LAST:event_txtNucleusInstanceURLKeyReleased


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnPushToNucleus;
    private javax.swing.JButton btnSyncWithNucleus;
    private javax.swing.JComboBox<String> cbProjects;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JProgressBar jProgressBar;
    private javax.swing.JPasswordField pwApiKey;
    private javax.swing.JTextField txtNucleusInstanceURL;
    // End of variables declaration//GEN-END:variables
}