/*
 * Copyright (c) 2020 Nucleus Security - All Rights Reserved
 */
package com.nucleussec.burpextension.view;

import burp.ExtensionStateListener;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import com.nucleussec.burpextension.controllers.NucleusApi;
import com.nucleussec.burpextension.utils.GlobalUtils;
import java.awt.Image;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.imageio.ImageIO;
import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import org.json.JSONException;

public class MainView extends javax.swing.JPanel {
    
    private IBurpExtenderCallbacks callbacks;
    private Preferences prefs;
    private NucleusApi nucleusApi;
    private ExtensionStateListener esl;
    private Thread thread;
    
    /**
     * Creates new form MainView
     */
    public MainView(IBurpExtenderCallbacks callbacks, ExtensionStateListener esl) {
        this.callbacks = callbacks;
        this.esl = esl;
        this.prefs = Preferences.userRoot().node(this.getClass().getName());
        this.nucleusApi = new NucleusApi(this, prefs);
        initComponents();
        
        populateScanUrlsList();
        
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
            setProgressBar(0);
        } catch(JSONException jex){
            Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, jex);
            setProgressBar(0);
        }
    }
    
    private void populateScanUrlsList() {
        LinkedHashSet<String> targetUrls = new LinkedHashSet<>();
        

        for(IHttpRequestResponse reqResp : callbacks.getSiteMap("")) {
            String host = reqResp.getHttpService().getProtocol() + "://" + reqResp.getHttpService().getHost();
            targetUrls.add(host);
        }
        
        ((DefaultListModel)listScanUrls.getModel()).removeAllElements();
        
        for(String targetUrl : targetUrls) 
            ((DefaultListModel)listScanUrls.getModel()).addElement(targetUrl);
    }
    
    private IScanIssue[] getScanIssues() {
        List<String> selectedUrls = listScanUrls.getSelectedValuesList();
        ArrayList<IScanIssue> scanIssues = new ArrayList();
        
        if(!selectedUrls.isEmpty()) {
            for(String selectedUrl : selectedUrls) {
                Collections.addAll(scanIssues, callbacks.getScanIssues(selectedUrl));
            }
        } else {
            Collections.addAll(scanIssues, callbacks.getScanIssues(""));
        }
        
        return scanIssues.toArray(new IScanIssue[scanIssues.size()]);
    }
    
    private void zipFile(File file) {
        try {
            FileOutputStream fos = new FileOutputStream(System.getenv("USERPROFILE")+"\\AppData\\Local\\Temp\\" + file.getName()+".zip");
            ZipOutputStream zipOut = new ZipOutputStream(fos);
            FileInputStream fis = new FileInputStream(file);
            ZipEntry zipEntry = new ZipEntry(file.getName());
            zipOut.putNextEntry(zipEntry);
            byte[] bytes = new byte[1024];
            int length;
            while((length = fis.read(bytes)) >= 0) {
                zipOut.write(bytes, 0, length);
            }
            zipOut.close();
            fis.close();
            fos.close();
        } catch (IOException ex) {
            Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, ex);
            setProgressBar(0);
        }
    }
    
    private void checkIfFileIsWritten(boolean isCompletelyWritten) {
        while(!isCompletelyWritten) {
            try {
                Thread.sleep(1000);
                jProgressBar.setValue(45);
            } catch (InterruptedException ex) {
                Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, ex);
                setProgressBar(0);
            }
        }
    }
    
    private void pushToNucleus() {
        long currentTime = System.currentTimeMillis();
        String fileName = System.getenv("USERPROFILE")+"\\AppData\\Local\\Temp\\nucleusBurpExtension-" + currentTime + ".xml";
        File file = new File(fileName);
        setProgressBar(15);
        thread = new Thread(new Runnable() {
            @Override
            public void run() {
                callbacks.generateScanReport("xml", getScanIssues(), file);
                jProgressBar.setValue(30);
                
                checkIfFileIsWritten(GlobalUtils.isCompletelyWritten(file));
                
                zipFile(file);
                String zipFileName = System.getenv("USERPROFILE")+"\\AppData\\Local\\Temp\\" + file.getName() + ".zip";
                File zipFile = new File(zipFileName);
                
                checkIfFileIsWritten(GlobalUtils.isCompletelyWritten(zipFile));
        
                try {
                    nucleusApi.uploadScanFile(zipFile, zipFile.getName());
                    jProgressBar.setValue(100);
                } catch (IOException ex) {
                    Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, ex);
                    setProgressBar(0);
                } catch(NullPointerException npe) {
                    Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, npe);
                    setProgressBar(0);
                    JOptionPane.showMessageDialog(MainView.this, "Failed to connect to Nucleus. Please make sure all fields are correct.", "Error has occured", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
       esl.setThread(thread);
       thread.start();
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

        jScrollPane2 = new javax.swing.JScrollPane();
        jPanel2 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        txtNucleusInstanceURL = new javax.swing.JTextField();
        pwApiKey = new javax.swing.JPasswordField();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        cbProjects = new javax.swing.JComboBox<>();
        btnSyncWithNucleus = new javax.swing.JButton();
        jLabel7 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        btnRefreshScanURLs = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        listScanUrls = new javax.swing.JList<>();
        btnPushToNucleus = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        jProgressBar = new javax.swing.JProgressBar();

        jLabel1.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(204, 102, 0));
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel1.setText("Configure Nucleus Server");

        jLabel5.setText("Nucleus Instance URL:");

        txtNucleusInstanceURL.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtNucleusInstanceURLKeyReleased(evt);
            }
        });

        pwApiKey.setText("jPasswordField1");

        jLabel2.setText("Nucleus API Key:");

        jLabel3.setText("Project:");

        btnSyncWithNucleus.setText("Sync with Nucleus");
        btnSyncWithNucleus.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSyncWithNucleusActionPerformed(evt);
            }
        });

        jLabel7.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel7.setForeground(new java.awt.Color(204, 102, 0));
        jLabel7.setText("Upload Results to Nucleus");
        jLabel7.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);

        jLabel6.setText("Select Scan URLs to Include:");

        btnRefreshScanURLs.setIcon(new javax.swing.ImageIcon(getClass().getResource("/refresh.png"))); // NOI18N
        btnRefreshScanURLs.setBorderPainted(false);
        btnRefreshScanURLs.setContentAreaFilled(false);
        btnRefreshScanURLs.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRefreshScanURLsActionPerformed(evt);
            }
        });

        listScanUrls.setModel(new DefaultListModel<String>());
        jScrollPane1.setViewportView(listScanUrls);

        btnPushToNucleus.setText("Upload Issues");
        btnPushToNucleus.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnPushToNucleusActionPerformed(evt);
            }
        });

        jLabel4.setText("Upload Status:");

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap(239, Short.MAX_VALUE)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 907, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addGroup(jPanel2Layout.createSequentialGroup()
                            .addComponent(jLabel2)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(pwApiKey, javax.swing.GroupLayout.PREFERRED_SIZE, 665, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(btnSyncWithNucleus))
                        .addGroup(jPanel2Layout.createSequentialGroup()
                            .addComponent(jLabel5)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(txtNucleusInstanceURL, javax.swing.GroupLayout.PREFERRED_SIZE, 776, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 908, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(jLabel6)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(btnRefreshScanURLs, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel2Layout.createSequentialGroup()
                            .addComponent(jLabel3)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(cbProjects, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGroup(jPanel2Layout.createSequentialGroup()
                            .addComponent(btnPushToNucleus, javax.swing.GroupLayout.PREFERRED_SIZE, 189, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 48, Short.MAX_VALUE)
                            .addComponent(jLabel4)
                            .addGap(18, 18, 18)
                            .addComponent(jProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, 568, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING)))
                .addContainerGap(239, Short.MAX_VALUE))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(35, 35, 35)
                .addComponent(jLabel1)
                .addGap(18, 18, 18)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(txtNucleusInstanceURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(pwApiKey, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnSyncWithNucleus))
                .addGap(18, 18, 18)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(cbProjects, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addGap(109, 109, 109)
                .addComponent(jLabel7)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(btnRefreshScanURLs, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(41, 41, 41)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel4)
                        .addComponent(btnPushToNucleus)))
                .addGap(721, 721, 721))
        );

        jScrollPane2.setViewportView(jPanel2);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2)
        );
    }// </editor-fold>//GEN-END:initComponents

    private void txtNucleusInstanceURLKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtNucleusInstanceURLKeyReleased
        prefs.put("instance_url", txtNucleusInstanceURL.getText());
    }//GEN-LAST:event_txtNucleusInstanceURLKeyReleased

    private void btnSyncWithNucleusActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSyncWithNucleusActionPerformed
        char[] apiKey = pwApiKey.getPassword();
        if(apiKey.length > 0) {
            prefs.put("x-apikey", String.valueOf(apiKey));
            populateProjectsComboBox();
        }
    }//GEN-LAST:event_btnSyncWithNucleusActionPerformed

    private void btnRefreshScanURLsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRefreshScanURLsActionPerformed
        btnRefreshScanURLs.setIcon(new javax.swing.ImageIcon(getClass().getResource("/refresh-sync.png"))); // NOI18N
        populateScanUrlsList();
        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                btnRefreshScanURLs.setIcon(new javax.swing.ImageIcon(getClass().getResource("/refresh.png"))); // NOI18N
            }
        }, 500);
    }//GEN-LAST:event_btnRefreshScanURLsActionPerformed

    private void btnPushToNucleusActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnPushToNucleusActionPerformed
        String errors = "";
        if (prefs.get("instance_url", "").isEmpty() || prefs.get("x-apikey", "").isEmpty() || txtNucleusInstanceURL.getText().isEmpty() || pwApiKey.getPassword().length == 0 | listScanUrls.isSelectionEmpty()) {
            JOptionPane.showMessageDialog(this, "Some fields appear to be empty or not selected. Please fill in or select these fields and try again.", "Error has occured", JOptionPane.ERROR_MESSAGE);
        } else pushToNucleus();
    }//GEN-LAST:event_btnPushToNucleusActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnPushToNucleus;
    private javax.swing.JButton btnRefreshScanURLs;
    private javax.swing.JButton btnSyncWithNucleus;
    private javax.swing.JComboBox<String> cbProjects;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JProgressBar jProgressBar;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JList<String> listScanUrls;
    private javax.swing.JPasswordField pwApiKey;
    private javax.swing.JTextField txtNucleusInstanceURL;
    // End of variables declaration//GEN-END:variables
}
