/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.awt.event.KeyEvent;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.RowFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

/**
 *
 * @author akurosu
 */
public class ReptruderThreadFrame extends JPanel {

    private BurpExtender parent;

    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    
    private RunProcess thread;
    public boolean thresIsWait = false;
    private ArrayList<ThreadResultInfo> allResultList = new ArrayList<>();
    private final int orgRequestNum;
    
    private TableRowSorter<TableModel> sorter;
    
    /**
     * Creates new form ReptruderThreadFrame
     */
    public ReptruderThreadFrame(BurpExtender prt, ArrayList<RequestEntry> reqlist) {
        
        this.parent = prt;
        this.orgRequestNum = reqlist.size();
        
        initComponents();
        initBurpUI();
        
        this.thread = new RunProcess(prt, reqlist, this);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jSplitPane2 = new javax.swing.JSplitPane();
        jPanel2 = new javax.swing.JPanel();
        runBtn = new javax.swing.JButton();
        jPanel1 = new javax.swing.JPanel();
        reqresSplitPane = new javax.swing.JSplitPane();
        restartBtn = new javax.swing.JButton();
        repeatNumText = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        filterText = new javax.swing.JTextField();
        filterCheck = new javax.swing.JCheckBox();
        jScrollPane1 = new javax.swing.JScrollPane();
        threadTable = new javax.swing.JTable();

        jSplitPane2.setDividerLocation(150);
        jSplitPane2.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        runBtn.setText("go");
        runBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                runBtnActionPerformed(evt);
            }
        });

        reqresSplitPane.setDividerLocation(350);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(reqresSplitPane, javax.swing.GroupLayout.DEFAULT_SIZE, 762, Short.MAX_VALUE)
                .addGap(5, 5, 5))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(reqresSplitPane)
                .addGap(10, 10, 10))
        );

        restartBtn.setText("restart");
        restartBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                restartBtnActionPerformed(evt);
            }
        });

        repeatNumText.setHorizontalAlignment(javax.swing.JTextField.RIGHT);
        repeatNumText.setText("1");

        jLabel1.setText("回");

        jLabel2.setText("#");

        filterCheck.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                filterCheckActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(runBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(repeatNumText, javax.swing.GroupLayout.PREFERRED_SIZE, 41, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(4, 4, 4)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(restartBtn)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(filterCheck)
                .addGap(3, 3, 3)
                .addComponent(jLabel2)
                .addGap(4, 4, 4)
                .addComponent(filterText, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
            .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(filterCheck)
                    .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(runBtn)
                        .addComponent(restartBtn)
                        .addComponent(repeatNumText, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel1)
                        .addComponent(jLabel2)
                        .addComponent(filterText, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(10, 10, 10)
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jSplitPane2.setBottomComponent(jPanel2);

        threadTable.setModel(new ResultDataModel(
            new Object [][] {

            },
            new String [] {
                "#", "URL", "length"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Integer.class, java.lang.String.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                false, false, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        threadTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                threadTableMouseClicked(evt);
            }
        });
        threadTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                threadTableKeyReleased(evt);
            }
        });
        jScrollPane1.setViewportView(threadTable);

        jSplitPane2.setLeftComponent(jScrollPane1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(5, 5, 5)
                .addComponent(jSplitPane2)
                .addGap(5, 5, 5))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(5, 5, 5)
                .addComponent(jSplitPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 567, Short.MAX_VALUE)
                .addGap(5, 5, 5))
        );
    }// </editor-fold>//GEN-END:initComponents

    /*
      Tableをクリックした際の挙動
    */
    private void threadTableMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_threadTableMouseClicked
        changeSelectReqRes();
    }//GEN-LAST:event_threadTableMouseClicked

    /*
    
    */
    private void changeSelectReqRes() {
        int displayRow = this.threadTable.getSelectedRow();
        int row = this.threadTable.convertRowIndexToModel(displayRow);
        if (this.allResultList.size() > row) {
            ThreadResultInfo result = this.allResultList.get(row);

            if (result != null) {
                this.requestViewer.setMessage(result.reqres.getRequest(), true);
                if (result.isEnd == true) {
                    this.responseViewer.setMessage(result.reqres.getResponse(), true);
                } else {
                    this.responseViewer.setMessage(new byte[0], true);
                }
            }
        } else {
            if (this.thresIsWait == true) {
                byte[] req = ((ResultDataModel)this.threadTable.getModel()).lastRequestEntry.getThreadRequest();
                    this.requestViewer.setMessage(req, true);
                    this.responseViewer.setMessage(new byte[0], true);            
            }
        }
    }
    /*
      runボタン
    */
    private void runBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_runBtnActionPerformed

        this.thread.watiChangedRequest = this.requestViewer.getMessage();
        
        synchronized (this.thread) {
            this.thread.notify();
        }
    }//GEN-LAST:event_runBtnActionPerformed

    private void restartBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_restartBtnActionPerformed

        // repeatボタンの場合
        if ("restart".equals(evt.getActionCommand()) == true) {
            // 指定回数取得
            String repeatNumString = this.repeatNumText.getText();
            int repeatNum = 0;
            try {
                repeatNum = Integer.valueOf(repeatNumString);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "1以上の数値を入力してください。");
                return;
            }

            ArrayList<RequestEntry> reqList = this.thread.getEndedRequestList(this.orgRequestNum);
            if (reqList.size() > 0) {

                // 指定回数分リストに追加する
                ArrayList<RequestEntry> repeatReqList = new ArrayList<>();
                for (int i=0; i<repeatNum; i++) {
                    repeatReqList.addAll(reqList);
                }
                
                List<ICookie> lastCookieList = this.thread.lastCookies;

                this.thread = new RunProcess(this.parent, repeatReqList, this);
                this.thread.setLastCookieList(lastCookieList);
                
                start();

                // stopボタンに切り替え
                this.switchRestartStop(false);
            }
        } else {// stopボタン

            this.thread.stopProcess();

            // スレッドが一時停止してる場合は再開させる
            synchronized (this.thread) {
                this.thread.notify();
            }
            
            // restartボタンに切り替え
            this.switchRestartStop(true);
        }
    }//GEN-LAST:event_restartBtnActionPerformed

    // 結果表示のフィルタ
    private void filterCheckActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_filterCheckActionPerformed

        if (this.filterCheck.isSelected() == true) {
            String filterString = this.filterText.getText();
            String filterRegexp = makeFilterRegexp(filterString);

            if (filterRegexp.length() == 0) {
                this.filterCheck.setSelected(false);
                return;
            }

            // sorterを作成
            sorter = new TableRowSorter<TableModel>(this.threadTable.getModel());

            sorter.setRowFilter(RowFilter.regexFilter(filterRegexp, 0));

            this.threadTable.setRowSorter(sorter);
        } else {
            this.threadTable.setRowSorter(null);
        }
    }//GEN-LAST:event_filterCheckActionPerformed

    private void threadTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_threadTableKeyReleased
        int keycode = evt.getKeyCode();
        if (keycode == KeyEvent.VK_UP || keycode == KeyEvent.VK_DOWN) {
            changeSelectReqRes();
        }
    }//GEN-LAST:event_threadTableKeyReleased

    /*
      カンマ区切りの数値を正規表現系にする
    */
    private String makeFilterRegexp(String filterString) {
        ArrayList<String> filterList = new ArrayList<>();
        for (String s: filterString.split("[,\\s]+")) {
            if (s.matches("^\\d+$") == true) {
                filterList.add(s);
            } else {
                // 入力値が不正
                return "";
            }
        }
        
        if (filterList.size() == 0) {
            // 入力値に数値無し
            return "";
        }
        
        StringBuilder ret = new StringBuilder("(");
        while(filterList.size() > 0) {
            String s = filterList.remove(0);
            if (filterList.size() > 0) {
                s = s + "|";
            }
            ret.append(s);
        }
        ret.append(")");
        
        return ret.toString();
    }
    
    /*
      GUI設定
    */
    private void initBurpUI() {
        // 左Paneへのコンポーネント配置
        requestViewer = this.parent.callbacks.createMessageEditor(null, true);
        responseViewer = this.parent.callbacks.createMessageEditor(null, false);
        
        reqresSplitPane.setLeftComponent(requestViewer.getComponent());
        reqresSplitPane.setRightComponent(responseViewer.getComponent());
        
        // Tableを行選択にする
        this.threadTable.setCellSelectionEnabled(false);
        this.threadTable.setRowSelectionAllowed(true);
        
        // #の列の幅を設定
        TableColumn col = this.threadTable.getColumnModel().getColumn(0);
        col.setMaxWidth(100);
    }
    
    /*
      thread start
    */
    public void start() {
        this.thread.start();
    }
    
    /*
      表に追加（リクエスト）
    */
    public void addReq(RequestEntry reqEntry) {
        ((ResultDataModel)this.threadTable.getModel()).addRequest(reqEntry);
        
        this.threadTable.validate();
        this.threadTable.repaint();
    }
    
    /*
      表に追加（結果）
    */
    public void addReqRes(ThreadResultInfo reqres) {
        ((ResultDataModel)this.threadTable.getModel()).addResult(reqres);
        
        this.threadTable.validate();
        this.threadTable.repaint();
    }
    
    /*
      一時停止時の処理
    */
    public void showPreRequest(RequestEntry reqEntry) {
        this.requestViewer.setMessage(reqEntry.getThreadRequest(), true);
    }
    
    /*
      結果を保持
    */
    public void addResult(ThreadResultInfo tri) {
        this.allResultList.add(tri);
    }
    
    /*
      restartとstopを切り替え
    */
    public void switchRestartStop(Boolean restart) {
        if (restart == true) {
            this.restartBtn.setText("restart");
            this.restartBtn.setActionCommand("restart");
        } else {
            this.restartBtn.setText("stop");
            this.restartBtn.setActionCommand("stop");
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox filterCheck;
    private javax.swing.JTextField filterText;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSplitPane jSplitPane2;
    private javax.swing.JTextField repeatNumText;
    private javax.swing.JSplitPane reqresSplitPane;
    private javax.swing.JButton restartBtn;
    private javax.swing.JButton runBtn;
    private javax.swing.JTable threadTable;
    // End of variables declaration//GEN-END:variables
}

class ResultDataModel extends DefaultTableModel {
    public RequestEntry lastRequestEntry = null;
    
    /*
      コンストラクタ
    */
    public ResultDataModel(Object[][] data, Object[] columnNames) {
        super(data, columnNames);
    }
    
    /*
      リクエストを追加
    */
    public void addRequest(RequestEntry reqEntry) {
        Object[] newReq = {reqEntry.getNumber(), reqEntry.getURL(), null};
        this.addRow(newReq);
        
        this.lastRequestEntry = reqEntry;
    }
    
    /*
      結果を追加
    */
    public void addResult(ThreadResultInfo reqres) {
        // 一つ前の、リクエストのみの行を削除
        this.removeRow(this.getRowCount() - 1);
        // 追加
        this.addRow(reqres.getTableModelObject());
    }
}

/*
  リクエスト送信クラス
*/
class RunProcess extends Thread {
    
    private BurpExtender parent;
    private ReptruderThreadFrame threadFrame;

    private ArrayList<RequestEntry> requestList = new ArrayList<>();
    private ArrayList<ThreadResultInfo> resultList = new ArrayList<>();
    private ArrayList<RequestEntry> endedList = new ArrayList<>();
    
    public List<ICookie> lastCookies = new ArrayList<>();
    
    public byte[] watiChangedRequest = null;
    
    private Boolean stopFlag = false;
        
    /*
      コンストラクタ
    */
    public RunProcess(BurpExtender prt, List<RequestEntry> reqlist, ReptruderThreadFrame ttf) {
        this.parent = prt;
        this.threadFrame = ttf;
        
        this.requestList = (ArrayList)reqlist;
        this.resultList = new ArrayList<>();
    }
    
    /*
      スレッド実行メソッド
    */
    @Override
    public void run(){
        
        this.threadFrame.switchRestartStop(false);
      
        while (requestList.size() > 0) {
            RequestEntry reqEntry = requestList.remove(0);
            reqEntry.initForThread();
            
            // skipフラグの確認
            if (reqEntry.isSkip() == true) {
                continue;
            }
            
            //CookieをUpdate
            if (reqEntry.getAcceptCookies() == true && lastCookies != null) {
                reqEntry.updateCookies(lastCookies);
//                for (ICookie c: lastCookies) 
//                    this.parent.printStr(c.getName() + ": " + c.getValue());
            } else {
                // 引き継がない場合はクリア
                lastCookies.clear();
            }
            
            // パラメータをアップデート
            this.updateParameters(reqEntry);
            
            // リクエストを表示
            this.threadFrame.addReq(reqEntry);
            
            // targetフラグがON
            if (reqEntry.isTarget == true) {
                this.threadFrame.showPreRequest(reqEntry);
                try {
                    synchronized (this) {
                        this.threadFrame.thresIsWait = true;
                        this.wait();
                        this.threadFrame.thresIsWait = false;
                    }
                    
                    if (this.watiChangedRequest != null) {
                        reqEntry.updateRequestBytes(watiChangedRequest);
                        watiChangedRequest = null;
                    }
                } catch (Exception e) {
                    this.parent.printErr(e);
                    break;
                }
            }
            
            // stopフラグ確認
            if (this.stopFlag == true) {
                // 整合性を保つために空の結果を追加
                IHttpRequestResponse tempReqRes = this.parent.callbacks.makeHttpRequest(reqEntry.getHttpService(), reqEntry.getThreadRequest());
                ThreadResultInfo nullResult = new ThreadResultInfo(tempReqRes, reqEntry.getNumber(), reqEntry.getURL());
                this.threadFrame.addResult(nullResult);
                this.endedList.add(reqEntry); 
                this.endedList.addAll(this.requestList);
                break;
            }

            // リクエストを送信
            IHttpRequestResponse res = sendRequest(reqEntry.getHttpService() ,reqEntry.getThreadRequest());
            
            // stopフラグ確認
            if (this.stopFlag == true) {
                // 整合性を保つために空の結果を追加
                IHttpRequestResponse tempReqRes = this.parent.callbacks.makeHttpRequest(reqEntry.getHttpService(), reqEntry.getThreadRequest());
                ThreadResultInfo nullResult = new ThreadResultInfo(tempReqRes, reqEntry.getNumber(), reqEntry.getURL());
                this.threadFrame.addResult(nullResult);
                this.endedList.add(reqEntry); 
                this.endedList.addAll(this.requestList);
                break;
            }
            
            // Cookieを保存
            saveLastResponseCookie(res.getResponse());
            
            ThreadResultInfo result = new ThreadResultInfo(res, reqEntry.getNumber(), reqEntry.getURL());
            result.isEnd = true;
            resultList.add(result);
            
            // 結果を表示
            this.threadFrame.addReqRes(result);
            
            // 終了したRequestEntryを保持
            this.endedList.add(reqEntry);
            this.threadFrame.addResult(result);
        }

        this.stopProcess();
    }

    /*
      リクエスト送信
    */
    private IHttpRequestResponse sendRequest(IHttpService serv, byte[] reqBytes) {
        
        // Content-Lengthをアップデート。リクエストを再構築することで自動的に更新されることを目論む。
        IRequestInfo reqInfo = this.parent.helpers.analyzeRequest(reqBytes);
        byte[] messageBody = Arrays.copyOfRange(reqBytes, reqInfo.getBodyOffset(), reqBytes.length);
        reqBytes = this.parent.helpers.buildHttpMessage(reqInfo.getHeaders(), messageBody);
        
        // デバッグ
//        this.parent.printStr(new String(reqBytes));
        
        IHttpRequestResponse res =
            this.parent.callbacks.makeHttpRequest(serv, reqBytes);
        
        // デバッグ
        String resHeader = "";
        if (res.getResponse() != null) {
            IResponseInfo resInfo = this.parent.helpers.analyzeResponse(res.getResponse());
            resHeader = "";
            for (int i=0;i<resInfo.getHeaders().size();i++) {
                resHeader += resInfo.getHeaders().get(i) + "\n";
            }
        }
//        this.parent.printStr(resHeader);
        
        return res;
    }
    
    /*
      Cookie確認
    */
    private void saveLastResponseCookie(byte[] resbytes) {
        List<ICookie> resCookies = this.parent.helpers.analyzeResponse(resbytes).getCookies();
        for (ICookie c: resCookies) {
            for (int i=0; i<lastCookies.size(); i++) {
                ICookie storedCookie = lastCookies.get(i);
                if (storedCookie.getName().equals(c.getName()) == true) {
                    lastCookies.remove(storedCookie);
                }
            }
            lastCookies.add(c);
        }
    }
    
    /*
      パラメータアップデート
    */
    public void updateParameters(RequestEntry reqentry) {
        if (reqentry.getPrepare() == true && reqentry.pp != null) {
            for (PreviousProcessInfo ppi: reqentry.pp.getProcessInfoList()) {
                // レスポンスの#番号を取得
                int resNum = ppi.targetResponseInfo.responseNumber;
                // RequestEntryのリストから、#番号が何番目かを確認
                int index = 0;
                for (index = resultList.size()-1; index>=0; index--) {
                    ThreadResultInfo re = resultList.get(index);
                    if (re.orgNumber == resNum) {
                        break;
                    }
                }
                // 受信しているレスポンス一覧から該当レスポンスを取得
                byte[] srcres = null;
                if (this.resultList.size() >= index + 1) {
                    ThreadResultInfo reqres = resultList.get(index);
                    srcres = reqres.reqres.getResponse();
                }

                reqentry.updateParameter(ppi, srcres);
            }
        }
    }
    
    /*
      結果取得
    */
    public ThreadResultInfo getResultByNumber(int number) {
        for (ThreadResultInfo result: this.resultList) {
            if (result.orgNumber == number) {
                return result;
            }
        }
        return null;
    }
    
    /*
      終了したリクエストリストを取得。ただし、スレッドが終了している場合
    */
    public ArrayList<RequestEntry> getEndedRequestList(int num) {
        
        ArrayList<RequestEntry> retList = new ArrayList<>();
           
        if (this.isAlive() == false) {
            int count = 0;
            while (count < num && this.endedList.size() > 0) {
                retList.add(this.endedList.remove(this.endedList.size() - 1));
                count++;
            }
            Collections.reverse(retList);
            this.endedList.clear();
        }
        
        return retList;
    }
    
    /*
      スレッド停止
    */
    public void stopProcess() {
        this.stopFlag = true;
        
        this.threadFrame.switchRestartStop(true);
    }
    
    /*
      Cookieをセット。Resttart引き継ぎ用
    */
    public void setLastCookieList(List<ICookie> cookieList) {
        this.lastCookies = cookieList;
    }
    
}

class ThreadResultInfo {
    public IHttpRequestResponse reqres;
    public int orgNumber;
    private URL url;
    
    public Boolean isEnd = false;
    
    public ThreadResultInfo (IHttpRequestResponse r, int n, URL u) {
        this.reqres = r;
        this.orgNumber = n;
        this.url = u;
    }
    
    public Object[] getTableModelObject() {
        String urlString = "";
        if (this.url != null) {
            urlString = this.url.toString();
        }
        String len = String.valueOf(reqres.getResponse().length);
        Object[] rowData = {orgNumber, urlString, len};
        
        return rowData;
    }
}

