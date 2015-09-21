package burp;

import java.lang.System;
import java.util.List;
import java.util.ArrayList;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.awt.FlowLayout;
import java.awt.Color;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.event.WindowAdapter;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URL;
import static java.util.Arrays.asList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JMenuItem;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JScrollPane;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.TransferHandler;
import javax.swing.event.ChangeEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.TableModel;


/*
    Burpから呼び出される
*/
public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener, IHttpListener, IProxyListener {
    
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;

    public FramePopup logsaveframe;
    public Reptruder reptruder;
    public JFrame reptruderFrame;

    private IHttpRequestResponse[] selectedmessages = null;

    public SessionHandlingTest sessionHandlingTest = null;
    
    /*
        Utilityとコールバックを登録
    */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.logsaveframe = null;

        this.callbacks.registerContextMenuFactory(this);
        this.callbacks.registerHttpListener(this);
        this.callbacks.registerProxyListener(this);

        // SessionHandling Test
        this.sessionHandlingTest = new SessionHandlingTest(this);
        this.callbacks.registerSessionHandlingAction(this.sessionHandlingTest);
    }

    /*
        右クリックメニューに項目を登録
    */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation menuinvo) {
        List<JMenuItem> menulist = new ArrayList<>();

        try {
            if (this.logsaveframe == null) {
                JMenuItem logsavemenu = new JMenuItem("Popup To SaveLogFrame");
                FramePopup popup = new FramePopup(this);
                logsavemenu.addActionListener(popup);
                menulist.add(logsavemenu);
            }
            byte invocontext = menuinvo.getInvocationContext();
            if (invocontext != IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE
                    && invocontext != IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE) {
                JMenuItem addmenu = new JMenuItem("Add to SaveLogFrame");
                this.selectedmessages = menuinvo.getSelectedMessages();
                addmenu.addActionListener(this);
                menulist.add(addmenu);
            
                // Reptruder Menu
                this.selectedmessages = menuinvo.getSelectedMessages();
                if (this.selectedmessages.length > 0) {
                    JMenuItem reptruderMenu = new JMenuItem("add Reptruder");
                    reptruderMenu.addActionListener(this);
                    menulist.add(reptruderMenu);
                }
            }
            
        } catch (Exception e) {
            this.printErr(e);
            menulist.clear();
        }

        return menulist;
    }

    /*
        メニューがクリックされた場合の処理
        ポップアップを表示し、選択したログを追加
    */
    @Override
    public void actionPerformed(ActionEvent ae) {
        try {
            // Reptruder
            if ("add Reptruder".equals(ae.getActionCommand()) == true) {
                if (this.reptruder == null) {
                    this.reptruderFrame = new JFrame();
                    this.reptruder = new Reptruder(this);
                    this.reptruderFrame.add(this.reptruder);
                    this.reptruderFrame.setSize(720, 500);
                }

                for (int i=0; i<this.selectedmessages.length; i++) {
                    IHttpRequestResponse reqres = this.selectedmessages[i];
                    this.reptruder.addRequest(reqres);
                }

                if (this.reptruderFrame.isVisible() == false) {
                    this.reptruderFrame.setVisible(true);
                    this.reptruderFrame.addComponentListener(reptruder);
                }


                this.reptruder.validate();
                this.reptruder.repaint();
            } else {

                if (this.logsaveframe == null) {
                    this.logsaveframe = new FramePopup(this);
                    this.logsaveframe.actionPerformed(ae);
                }
                this.logsaveframe.makeAndAddLogString(this.selectedmessages);
            }

            this.selectedmessages = null;
        } catch (Exception e) {
            this.printErr(e);
        }
    }

    /*
        ポップアップクローズ処理用
    */
    public void closeframe() {
        this.logsaveframe = null;
    }

    /*
        通信をフック
        フラグがONの場合、ログ保存用ポップアップに通信ログをためる
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        try {
            if (this.logsaveframe != null) {
                synchronized (this.logsaveframe) {
                    if (this.logsaveframe.getRunningFlag() == true
                            && messageIsRequest == false) {
                        IHttpRequestResponse[] reqresarr = {messageInfo};
                        this.logsaveframe.makeAndAddLogString(reqresarr);
                    }
                }
            }
        } catch (Exception e) {
            this.printErr(e);
        }
    }

    /*
        通信をフック
        実際のリクエストURLをCommentに記録する
    */
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        try {

//            message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK);

            // set url info in comment
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            URL tempurl = this.helpers.analyzeRequest(messageInfo).getUrl();
            IHttpService ms = messageInfo.getHttpService();
            String urldetail = ms.getProtocol() + "://" + ms.getHost() + ":" + ms.getPort()
                    + tempurl.getFile();
            messageInfo.setComment(urldetail);
            
            // 自動インターセプト
            if (this.logsaveframe != null) {
                if (messageIsRequest == true) {                
                    boolean checkedAutoIntercept = this.logsaveframe.isCheckedAutoIntercept();
                    if (checkedAutoIntercept == true) {
                        boolean shouldIntercept = this.logsaveframe.checkAutoIntercept(messageInfo);
                        if (shouldIntercept == true) {
                            message.setInterceptAction(IInterceptedProxyMessage.ACTION_DO_INTERCEPT);
                        }
                    }
                }
            }
        } catch (Exception e) {
            this.printErr(e);
        }
    }

    /*
        Extensionクローズ時の後処理
    */
    public void extensionUnloaded() {
        try {
            this.logsaveframe = null;
            this.callbacks.removeContextMenuFactory(this);
            this.callbacks = null;
        } catch (Exception e) {
            this.printErr(e);
        }
    }

    /*
        例外を出力する
    */
    public void printErr(Exception e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        pw.flush();
        String errstr = e.getMessage() + "\r\n" + sw.toString();

        this.callbacks.printError(errstr);
    }

    /*
        開発用：文字列をExtensionタブに表示する
    */
    public void printStr(String str) {
        this.callbacks.printError(str + "\r\n");
    }

}

/*
    パラメータ差分のサマリを表示し、保存する
*/
class CompareSaveFrame extends WindowAdapter implements ActionListener {

    private FramePopup parent;
    private List<LogEntry> loglist;
    private final String encoding;

    private JFrame frame;
    private JTextField dispfield;
    private JTextArea textarea;

    /*
        コンストラクタ
    */
    public CompareSaveFrame(FramePopup parent, List<LogEntry> loglist, String encoding) {
        this.parent = parent;
        this.loglist = loglist;
        this.encoding = encoding;
    }

    /*
        ポップアップを作成
    */
    public void createWindow() {

        try {
            JFrame jframe = new JFrame("Compare Save Frame");
            jframe.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            jframe.setSize(480, 360);

            JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton saveBtn = new JButton("save");
            
            saveBtn.addActionListener(this);

            panel.add(saveBtn);

            JTextArea jtextarea = new JTextArea();
            JScrollPane scrollpane = new JScrollPane();
            scrollpane.setViewportView(jtextarea);

            jframe.add(panel, BorderLayout.PAGE_START);
            jframe.add(scrollpane, BorderLayout.CENTER);

            this.frame = jframe;
            this.textarea = jtextarea;

            jframe.addWindowListener(this);

            this.compareParamsToText();

            jframe.setVisible(true);

        } catch (Exception e) {
            this.parent.parent.printErr(e);
        }
    }
    
    /*
        ボタンクリック時の処理
    */
    @Override
    public void actionPerformed(ActionEvent ae) {
        try {
            if ("save".equals(ae.getActionCommand()) == true) {
                String textareatext = this.textarea.getText();
                this.parent.saveLogs(textareatext + "\r\n\r\n");
            }
        } catch (Exception e) {
            this.parent.parent.printErr(e);
        }
    }

    /*
        ログを比較し、結果を表示
    */
    private void compareParamsToText() {
        try {
            if (this.loglist.size() > 0) {

                String result = this.makeComparedResult(this.loglist);

                this.textarea.setText(result);

            }
        } catch (Exception e) {
            this.parent.parent.printErr(e);
        }
    }

    /*
        make compared result text
    */
    private String makeComparedResult(List<LogEntry> logslist) {
        StringBuilder ret = new StringBuilder();

        // 変更前ログ
        RequestParamList baseparams = null;
        for (LogEntry log : logslist) {
            if (log.baseflag == true) {
                baseparams = log.reqres2header(this.parent.parent.helpers);
                break;
            }
        }
        
        if (baseparams != null) {
            int count = 1;
            for (LogEntry log : loglist) {

                RequestParamList targetparams = log.reqres2header(this.parent.parent.helpers);

                StringBuilder eachResult = new StringBuilder();
                
                // 比較元の場合
                if (log.baseflag == true) {
                    eachResult.append(" base log" + "\r\n");
                }

                String modresult = this.checkModifiedValue(baseparams, targetparams);
                String addresult = this.checkAddValue(baseparams, targetparams);
                String notresult = this.checkNothingValue(baseparams, targetparams);

                if (modresult != null) {
                    eachResult.append(modresult);
                }
                if (addresult != null) {
                    eachResult.append(addresult);
                }
                if (notresult != null) {
                    eachResult.append(notresult);
                }

                // 差分無しの場合
                if (eachResult.length() == 0) {
                    eachResult.append("no diff" + "\r\n");
                }
                
                // レスポンスサイズ
                int ressize = 0;
                if (log.requestResponse != null && log.requestResponse != null) {
                    ressize = log.requestResponse.getResponse().length;
                }

                ret.append(String.valueOf(count) + ":" + String.valueOf(ressize) + "\r\n");
                ret.append(eachResult);

                count++;
            }
        } else {
            ret.append("undefined base log");
        }

        return ret.toString();
    }

    /*
        check modified
    */
    private String checkModifiedValue(RequestParamList baseList, RequestParamList targetList) {
        StringBuilder ret = new StringBuilder();

        String bmod = "(+)";
        String tmod = "(-)";
        String mmod = "(*)";

        for (RequestParam base : baseList.params) {
            int index = targetList.hasKey(base.name);
            if (index == -1) {
                continue;
            }

            RequestParam target = targetList.params.get(index);

            if (target.value.equals(base.value) == true) {
                continue;
            }

            int tindex = base.value.indexOf(target.value);
            int bindex = target.value.indexOf(base.value);
            if (tindex >= 0) {
                String temp = " mod:" + target.name + ":" + base.value.replace(target.value, tmod);
                ret.append(temp + "\r\n");
            } else if (bindex >= 0) {
                String temp = " mod:" + base.name + ":" + target.value.replace(base.value, bmod);
                ret.append(temp + "\r\n");
            } else {
                // middle modified
                int modstart = 0;
                int minlen = (base.value.length() > target.value.length()) ? target.value.length() : base.value.length();
                for (int i = 0; i < minlen; i++) {
                    if (base.value.charAt(i) != target.value.charAt(i)) {
                        modstart = i;
                        break;
                    }
                }
                int bi, ti;
                int modend = target.value.length() - 1;
                for (bi = base.value.length()-1, ti = target.value.length()-1;
                    bi >= 0 && ti >= 0; bi--, ti--) {
                    if (base.value.charAt(bi) != target.value.charAt(ti)) {
                        modend = ti;
                        break;
                    }
                }
                
                StringBuilder tempBuilder = new StringBuilder(" mod:" + base.name + ":");
                if (modstart > 0) tempBuilder.append(mmod);
                tempBuilder.append(target.value.substring(modstart, modend+1));
                if (modend != target.value.length() - 1) tempBuilder.append(mmod);
                ret.append(tempBuilder.toString() + "\r\n");
            }
        }

        return ret.toString();
    }

    /*
        check nothing
    */
    private String checkNothingValue(RequestParamList baseList, RequestParamList targetList) {
        StringBuilder ret = new StringBuilder();

        for (RequestParam base : baseList.params) {
            if (base.name.length() > 0 && targetList.hasKey(base.name) == -1) {
                String temp = " del:" + base.name + ":" + "\r\n";
                ret.append(temp);
            }
        }

        return ret.toString();
    }

    /*
        check add
    */
    private String checkAddValue(RequestParamList baseList, RequestParamList targetList) {
        StringBuilder ret = new StringBuilder();

        for (RequestParam target : targetList.params) {
            if (target.name.length() > 0 && baseList.hasKey(target.name) == -1) {
                String temp = " add:" + target.name + ":" + target.value + "\r\n";
                ret.append(temp);
            }
        }

        return ret.toString();
    }

    /*
        ポップアップクローズ時の処理
    */
    @Override
    public void windowClosing(WindowEvent we) {
        this.parent = null;
        this.loglist = null;

        super.windowClosing(we);
    }

}

/*
    ログ保存用のポップアップ
*/
class FramePopup extends WindowAdapter implements ActionListener, ItemListener, TableModel, IMessageEditorController {

    public BurpExtender parent;
    private List<LogEntry> loglist;
    private String encoding;
    private boolean running;
    private String savepath;
    private IHttpRequestResponse currentlyDisplayedItem;

    private JButton startBtn;
    private JFrame frame;
    private JComboBox combobox;
    private Table logtable;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private CompareSaveFrame compsaveFrame;
    private JCheckBox autoInterceptCheckbox;

    AutoInterceptSetting autoInterceptSetting;
        
    /*
        コンストラクタ
    */
    public FramePopup(BurpExtender parent) {
        this.parent = parent;
        this.loglist = new ArrayList<>();
        this.encoding = "utf-8";
        this.running = false;
        this.savepath = null;
        this.compsaveFrame = null;
    }

    /*
        ポップアップを表示
    */
    @Override
    public void actionPerformed(ActionEvent ae) {
        try {
            if ("Popup To SaveLogFrame".equals(ae.getActionCommand()) == true
                    || "Add to SaveLogFrame".equals(ae.getActionCommand()) == true) {
                JFrame jframe = new JFrame("Save Log Frame");
                jframe.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                jframe.setSize(720, 520);

                JSplitPane splitpane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitpane.setDividerLocation(200);

                JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                JButton jstartBtn = new JButton("start");
                JButton jsaveBtn = new JButton("save");
                JButton jclearBtn = new JButton("clear");
                JButton jcompsaveBtn = new JButton("comp save");
                JButton jpasteBtn = new JButton("paste");

                jstartBtn.setBackground(Color.LIGHT_GRAY);
                jstartBtn.addActionListener(this);
                this.startBtn = jstartBtn;
                jsaveBtn.addActionListener(this);
                jclearBtn.addActionListener(this);
                jcompsaveBtn.addActionListener(this);
                jpasteBtn.addActionListener(this);

                String[] combodata = {"utf-8", "shift_jis", "euc_jp", "ISO2022JP", "Windows-31J"};
                JComboBox combo = new JComboBox(combodata);
                combo.addItemListener(this);
                
                JCheckBox jintercept = new JCheckBox("auto Intercept");
                jintercept.addActionListener(this);

                panel.add(jstartBtn);
                panel.add(jsaveBtn);
                panel.add(jclearBtn);
                panel.add(combo);
                panel.add(jcompsaveBtn);
                panel.add(jpasteBtn);
                panel.add(jintercept);

                Table jlogtable = new Table(this);
                this.logtable = jlogtable;
                JScrollPane scrollpane = new JScrollPane(jlogtable);
                splitpane.setLeftComponent(scrollpane);

                JTabbedPane tabs = new JTabbedPane();
                requestViewer = this.parent.callbacks.createMessageEditor(null, false);
                responseViewer = this.parent.callbacks.createMessageEditor(null, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitpane.setRightComponent(tabs);

                jframe.add(panel, BorderLayout.PAGE_START);
                jframe.add(splitpane, BorderLayout.CENTER);

                this.frame = jframe;
                this.combobox = combo;
                this.parent.logsaveframe = this;
                this.autoInterceptCheckbox = jintercept;

                jframe.addWindowListener(this);
                
                jframe.setTransferHandler(new DropFileHandler(this));
                
                // 自動インターセプト設定
                this.autoInterceptSetting = new AutoInterceptSetting(this.frame, this, this.parent.callbacks, false);
                this.autoInterceptSetting.init();

                jframe.setVisible(true);

            } else if ("start".equals(ae.getActionCommand()) == true) {
                this.startAction();
            } else if ("stop".equals(ae.getActionCommand()) == true) {
                this.stopAction();
            } else if ("clear".equals(ae.getActionCommand()) == true) {
                this.clearText();
            } else if ("save".equals(ae.getActionCommand()) == true) {
                this.saveLogs(null);
            } else if ("comp save".equals(ae.getActionCommand()) == true) {
                this.compSave();
            } else if ("paste".equals(ae.getActionCommand()) == true) {
                this.pasteLogs();
            } else if ("auto Intercept".equals(ae.getActionCommand()) == true) {
                if (this.autoInterceptCheckbox.isSelected() == true) {
                    this.autoInterceptSetting.setVisible(true);
                }
            }
        } catch (Exception e) {
            this.parent.printErr(e);
        }
    }

    /*
        MyReqRes形式に変換し、一覧に追加
    */
    private void pasteLogs() {
        try {
            Toolkit kit = Toolkit.getDefaultToolkit();
            Clipboard clip = kit.getSystemClipboard();
            
            String clipstr = (String)clip.getData(DataFlavor.stringFlavor);
            
            this.readStrLogs(clipstr);
            
        } catch (Exception e) {
            this.parent.printErr(e);
        }
    }
    
    /*
        ログテキストからMyReqRes形式に変換し、一覧に追加
    */
    private void readStrLogs (String strlogs) {

        try {
            List<MyReqRes> rrlist = new ArrayList<>();
            String[] splited = strlogs.split("[\r\n]*======================================================[\r\n]+");
            
            MyReqRes eachrr = null;
            int beforeType = 0;
            for (int i = 0; i < splited.length; i++) {
                String eachstr = splited[i];

                int strtype = this.checkLogType(eachstr);
                if (strtype == 1) {
                    // ヘッダの場合、その直前までのログをリストに追加
                    if (eachrr != null) {
                        rrlist.add(eachrr);
                        eachrr = null;
                    }

                    MyHttpService hs = MyHttpService.createMyService(eachstr);
                    if (hs != null) {
                        eachrr = new MyReqRes(hs);
                        eachrr.setComment(eachstr.trim());
                        beforeType = 1;
                    } else {
                        eachrr = null;
                        beforeType = 0;
                    }
                } else if (strtype == 2 && beforeType == 1 && eachrr != null) {
                    eachrr.setRequest(eachstr.getBytes());
                    beforeType = 2;
                } else if (strtype == 3 && beforeType == 2 && eachrr != null) {
                    eachrr.setResponse(eachstr.getBytes());
                    beforeType = 3;
                }
            }
            if (eachrr != null) {
                rrlist.add(eachrr);
                eachrr = null;
            }

            // 一覧に追加
            this.makeAndAddLogString(rrlist.toArray(new MyReqRes[0]));

        } catch (Exception e) {
            this.parent.printErr(e);
        }
    }
    
    /*
        ログの文字列から、ヘッダかリクエストかレスポンスかを判断
        ヘッダ：1
        リクエスト：2
        レスポンス：3
        その他：0
    */
    private int checkLogType (String strlog) {

        Pattern preq = Pattern.compile("^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS)\\s");
        Matcher mreq = preq.matcher(strlog);
        if (mreq.find() == true) {
            return 2;
        }
        
        Pattern pres = Pattern.compile("^HTTP\\/\\d\\.\\d\\s\\d{3}");
        Matcher mres = pres.matcher(strlog);
        if (mres.find() == true) {
            return 3;
        }
        
        // 順番大事
        Pattern phead = Pattern.compile("https?:\\/\\/[\\w\\.\\-]+:?\\d*");
        Matcher mhead = phead.matcher(strlog);
        if (mhead.find() == true) {
            return 1;
        }
        
        return 0;
    }
    
    /*
        ドラッグ＆ドロップ処理
    */
    private class DropFileHandler extends TransferHandler {
 
        private FramePopup parent;
        
        public DropFileHandler(FramePopup frame) {
            this.parent = frame;
        }
 
        /**
         * ドロップされたものを受け取るか判断 (ファイルのときだけ受け取る)
         */
        @Override
        public boolean canImport(TransferSupport support) {
            if (!support.isDrop()) {
                // ドロップ操作でない場合は受け取らない
                return false;
            }

            if (!support.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                // ドロップされたのがファイルでない場合は受け取らない
                return false;
            }

            return true;
        }

        /**
         * ドロップされたファイルを受け取る
         */
        @Override
        public boolean importData(TransferSupport support) {

            boolean ret = false;
            // 受け取っていいものか確認する
            if (!canImport(support)) {
                return ret;
            }

            // ドロップ処理
            Transferable t = support.getTransferable();
            FileInputStream fis = null;
            InputStreamReader isr = null;
            BufferedReader br = null;
            try {
                // ファイルを受け取る
                List<File> files = (List<File>) t.getTransferData(DataFlavor.javaFileListFlavor);

                StringBuilder filelogstr = new StringBuilder();
                for (File file : files){
                    fis = new FileInputStream(file);
                    isr = new InputStreamReader(fis, this.parent.encoding);
                    br = new BufferedReader(isr);

                    String line;
                    while((line = br.readLine()) != null) {
                        filelogstr.append(line);
                        filelogstr.append("\r\n");
                    }
                    
                    br.close();
                    isr.close();
                    fis.close();
                }
                br = null; isr = null; fis = null;

                // 親クラスのログ解析、一覧追加の機能を呼び出す
                this.parent.readStrLogs(filelogstr.toString());

                ret = true;
            } catch (Exception e) {
                this.parent.parent.printErr(e);
            } finally {
                try {
                    if (br != null) {
                        br.close();
                    }
                    if (isr != null) {
                        isr.close();
                    }
                    if (fis != null) {
                        fis.close();
                    }
                } catch (Exception e) {
                    this.parent.parent.printErr(e);
                }
            }
            
            return ret;
        }
    }
    
    /*
        ログのリストをbyte列のリストに変換
    */
    private List<byte[]> getAllLogBytes() {
        List<byte[]> alllogbytes = new ArrayList<>();
        for (LogEntry log : this.loglist) {
            alllogbytes.addAll(this.makeLogBytes(log));
        }

        return alllogbytes;
    }

    /*
        Burpのログクラスから、内部で使用しているLogEntryクラスに変換
        URLはComment内の文字列を利用
    */
    public void makeAndAddLogString(IHttpRequestResponse[] reqresList) {
        for (IHttpRequestResponse reqres : reqresList) {
            URL url;
            String itemComment = reqres.getComment();
            if (itemComment != null && itemComment.startsWith("http") == true) {
                try {
                    url = new URL(itemComment);
                } catch (Exception e) {
                    url = this.parent.helpers.analyzeRequest(reqres).getUrl();
                    this.parent.printErr(e);
                }
            } else {
                url = this.parent.helpers.analyzeRequest(reqres).getUrl();
            }
            
            LogEntry log = new LogEntry(0, this.parent.callbacks.saveBuffersToTempFiles(reqres),
                            url);

            if (this.loglist.size() == 0) {
                log.baseflag = true;
            }
            this.loglist.add(log);
            
        }

        this.logtable.revalidate();
        this.logtable.repaint();
    }

    /*
        ログ保存用の形式をbyte配列で作成
    */
    public List<byte[]> makeLogBytes(LogEntry log) {
        List<byte[]> retbyes = new ArrayList<>();

        byte[] req = log.requestResponse.getRequest();
        byte[] res = log.requestResponse.getResponse();
        URL url = log.url;

        retbyes.add("======================================================\n".getBytes());
        retbyes.add((log.url.toString() + "\n").getBytes());
        retbyes.add("======================================================\n\n".getBytes());

        retbyes.add("======================================================\n".getBytes());
        retbyes.add(req);
        retbyes.add("\n".getBytes());
        

        if (res != null) {
            retbyes.add("======================================================\n".getBytes());
            retbyes.add(res);
            retbyes.add("\n".getBytes());
        }

        retbyes.add("======================================================\n\n\n".getBytes());

        return retbyes;
    }

    /*
        文字コード選択時の処理
    */
    @Override
    public void itemStateChanged(ItemEvent ie) {
        try {
            if (ie.getStateChange() == ItemEvent.SELECTED) {
                this.encoding = String.valueOf(this.combobox.getSelectedItem());
                this.logtable.changeEncoding();
            }
        } catch (Exception e) {
            this.parent.printErr(e);
        }
    }

    /*
        ログ保存処理
    */
    public void saveLogs(String header) {
        try {
            JFileChooser filechooser = new JFileChooser(this.savepath) {
                @Override
                public void approveSelection() {
                    File f = getSelectedFile();
                    if (f.exists() && getDialogType() == SAVE_DIALOG) {
                        String om = "Do You Wish to Overwrite?";
                        int rv = JOptionPane.showConfirmDialog(this, om, "Save as", JOptionPane.YES_NO_OPTION);
                        if (rv != JOptionPane.YES_OPTION) {
                            return;
                        }
                    }
                    super.approveSelection();
                }
            };

            int selected = filechooser.showSaveDialog(this.frame);
            if (selected == JFileChooser.APPROVE_OPTION) {
                File fileinfo = filechooser.getSelectedFile();

                List<byte[]> alllogbytes = this.getAllLogBytes();

                FileOutputStream fos = new FileOutputStream(fileinfo);
                try (BufferedOutputStream bos = new BufferedOutputStream(fos)) {

                    if (header != null) {
                        byte[] temp = header.getBytes(this.encoding);
                        bos.write(temp);
                    }
                    
                    for (byte[] logbyte : alllogbytes) {
                        bos.write(logbyte);
                    }

                    bos.flush();
                }

                this.savepath = fileinfo.getParent();
            }
        } catch (Exception e) {
            this.parent.printErr(e);
        }
    }

    /*
        ログ比較ポップアップを表示
    */
    private void compSave() {
        this.compsaveFrame = new CompareSaveFrame(this, this.loglist, this.encoding);
        this.compsaveFrame.createWindow();
    }

    /*
        ためたログをクリア
    */
    private void clearText() {
        this.loglist.clear();
        this.logtable.validate();
        this.logtable.repaint();
        this.requestViewer.setMessage(null, true);
        this.responseViewer.setMessage(null, false);

        System.gc();
    }

    /*
        通信をフックしてログをためる処理開始
    */
    private void startAction() {
        this.startBtn.setText("stop");
        this.startBtn.setBackground(Color.GRAY);
        this.running = true;
        
//        byte[] reqbyte = this.requestViewer.getMessage();
//        if (reqbyte != null && reqbyte.length > 0) {
//            IRequestInfo reqinfo = this.parent.helpers.analyzeRequest(reqbyte);
//            List<String> headers = reqinfo.getHeaders();
//            String firstHeader = headers.get(0);
//            int startPathIndex = firstHeader.indexOf(" ") + 1;
//            int lastPathIndex = firstHeader.lastIndexOf(" ");
//            String path = firstHeader.substring(startPathIndex, lastPathIndex);
//            
////            URL url = reqinfo.getUrl();
////            String path = url.getPath();
//            this.parent.printStr(path);
//        }
        
    }

    /*
        ログのフックを修了
    */
    private void stopAction() {
        this.startBtn.setText("start");
        this.startBtn.setBackground(Color.LIGHT_GRAY);
        this.running = false;
    }

    /*
        ログをフック中か否かの状態を返却
    */
    public boolean getRunningFlag() {
        return this.running;
    }
 
    /*
        ログ比較の基となるログを選択
    */
    public void selectBaseLog(int index) {
        for (int i = 0; i < this.loglist.size(); i++) {
            this.loglist.get(i).baseflag = false;
        }
        this.loglist.get(index).baseflag = true;
    }
    
    /*
        インターセプト条件のチェック
    */
    public boolean checkAutoIntercept(IHttpRequestResponse message) {
        return this.autoInterceptSetting.checkCondition(message);
    }
    
    /*
        自動インターセプトのダイアログがsaveされずに閉じられた時
    */
    public void uncheckAutoIntercept() {
        this.autoInterceptCheckbox.setSelected(false);
    }
    
    /*
        自動インターセプトがONかどうか
    */
    public boolean isCheckedAutoIntercept() {
        return this.autoInterceptCheckbox.isSelected();
    }

    /*
        ポップアップクローズ時の処理
    */
    @Override
    public void windowClosing(WindowEvent we) {
        this.stopAction();
        this.loglist.clear();
        this.encoding = "utf-8";
        this.frame = null;
        this.parent.closeframe();
        this.parent = null;
        this.autoInterceptSetting = null;

        super.windowClosing(we);

        System.gc();
    }

    //
    // テーブル用のメソッド類
    //
    @Override
    public int getRowCount() {
        return this.loglist.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "BASE";
            case 1:
                return "RES_SIZE";
            case 2:
                return "URL";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = this.loglist.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return logEntry.tableLabel();
            case 1:
                byte[] res = logEntry.requestResponse.getResponse();
                int reslength = 0;
                if (res != null) {
                    reslength = res.length;
                }
                return String.valueOf(reslength);
            case 2:
                return logEntry.url.toString();
            default:
                return "";
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
    }

    @Override
    public void addTableModelListener(TableModelListener l) {
    }

    @Override
    public void removeTableModelListener(TableModelListener l) {
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    /*
        ログ表示用のテーブル内部クラス
    */
    private class Table extends JTable {

        /*
            右クリック処理用内部クラス
        */
        private class MenuByRightClick extends JPopupMenu implements MouseListener {

            Table parent;

            /*
                右クリック時のメニュー作成
            */
            public MenuByRightClick(Table p) {
                this.parent = p;

                JMenuItem del1 = new JMenuItem("delete");
                JMenuItem base = new JMenuItem("select base");
                JMenuItem req2comp = new JMenuItem("send to Comparer (Request)");
                JMenuItem res2comp = new JMenuItem("send to Comparer (Response)");
                JMenuItem req2aisetting = new JMenuItem("send to Auto Intercept Setting");
                del1.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent ae) {
                        MenuByRightClick.this.parent.clickedMenuDel1();
                    }
                });
                base.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent ae) {
                        MenuByRightClick.this.parent.clickedSelectBase();
                    }
                });
                req2comp.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent ae) {
                        MenuByRightClick.this.parent.clickedReq2Comp();
                    }
                });
                res2comp.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent ae) {
                        MenuByRightClick.this.parent.clickedRes2Comp();
                    }
                });
                req2aisetting.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent ae) {
                        MenuByRightClick.this.parent.send2AutoIntercept();
                    } 
                });
                this.add(base);
                this.add(del1);
                this.add(req2comp);
                this.add(res2comp);
                this.add(req2aisetting);
            }

            /*
                右クリック時、メニューを表示する
            */
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    popupmenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {

            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        }

        private FramePopup parent;
        private MenuByRightClick popupmenu;

        /*
            コンストラクタ
        */
        public Table(FramePopup parent) {
            super(parent);

            this.parent = parent; 
            
            popupmenu = new MenuByRightClick(this);

            this.addMouseListener(popupmenu);

            this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            DefaultTableColumnModel colmodel = (DefaultTableColumnModel) this.getColumnModel();
            colmodel.getColumn(0).setPreferredWidth(50);
            colmodel.getColumn(1).setPreferredWidth(100);
            colmodel.getColumn(2).setPreferredWidth(550);
        }
        
        /*
            選択したログを削除
        */
        public void clickedMenuDel1() {
            List<LogEntry> targets = new ArrayList<>();
            int[] rindexs = this.getSelectedRows();
            for (int rindex : rindexs) {
                targets.add(FramePopup.this.loglist.get(rindex));
            }
            FramePopup.this.loglist.removeAll(targets);

            byte[] nullreq = new byte[0];
            byte[] nullres = new byte[0];
            FramePopup.this.requestViewer.setMessage(nullreq, true);
            FramePopup.this.responseViewer.setMessage(nullres, false);
            this.clearSelection();

            this.validate();
            this.repaint();
        }
        
        /*
            選択したログをComparerに
        */
        public void clickedReq2Comp() {
            int[] rindexs = this.getSelectedRows();
            for (int rindex : rindexs) {
                LogEntry le = FramePopup.this.loglist.get(rindex);
                this.parent.parent.callbacks.sendToComparer(le.requestResponse.getRequest());
            }
        }
        /*
            選択したログをComparerに
        */
        public void clickedRes2Comp() {
            int[] rindexs = this.getSelectedRows();
            for (int rindex : rindexs) {
                LogEntry le = FramePopup.this.loglist.get(rindex);
                this.parent.parent.callbacks.sendToComparer(le.requestResponse.getResponse());
            }
        }

        /*
            ログ比較の基となるログを選択
        */
        public void clickedSelectBase() {
            int[] rindexs = this.getSelectedRows();
            for (int rindex : rindexs) {
                FramePopup.this.selectBaseLog(rindex);
            }

            this.validate();
            this.repaint();
        }
        
        /*
            選択したログを自動インターセプト設定に渡す
        */
        public void send2AutoIntercept() {
            int[] rindexs = this.getSelectedRows();
            for (int rindex : rindexs) {
                LogEntry le = FramePopup.this.loglist.get(rindex);
                AutoInterceptSetting ais = this.parent.autoInterceptSetting;
                ais.getConditions().setTestMessage(le.requestResponse);
                ais.visibleTestMessage();

                break;
            }
        }

        /*
            選択されている文字エンコードに変換する
        */
        public void changeEncoding() {
            try {
                IHttpRequestResponse reqres = FramePopup.this.currentlyDisplayedItem;
                if (reqres != null) {
                    byte[] reqbytes = (new String(reqres.getRequest(), FramePopup.this.encoding)).getBytes();
                    byte[] resbytes = null;
                    byte[] tempresbytes = reqres.getResponse();
                    if (tempresbytes != null) {
                        resbytes = (new String(tempresbytes, FramePopup.this.encoding)).getBytes();
                    }
                    FramePopup.this.requestViewer.setMessage(reqbytes, true);
                    FramePopup.this.responseViewer.setMessage(resbytes, false);

                    this.validate();
                    this.repaint();
                }
            } catch (Exception e) {
                FramePopup.this.parent.printErr(e);
            }
        }

        /*
            ログを選択した際の処理
        */
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            try {
                LogEntry logentry = FramePopup.this.loglist.get(row);
                byte[] reqbytes = (new String(logentry.requestResponse.getRequest(), FramePopup.this.encoding)).getBytes();
                byte[] resbytes = null;
                byte[] tempresbytes = logentry.requestResponse.getResponse();
                if (tempresbytes != null) {
                    resbytes = (new String(tempresbytes, FramePopup.this.encoding)).getBytes();
                }
                FramePopup.this.requestViewer.setMessage(reqbytes, true);
                if (resbytes != null) {
                    FramePopup.this.responseViewer.setMessage(resbytes, false);
                }
                FramePopup.this.currentlyDisplayedItem = logentry.requestResponse;

                super.changeSelection(row, col, toggle, extend);
            } catch (Exception e) {
                FramePopup.this.parent.printErr(e);
            }
        }

    }
}

/*
    ログの内部保持用クラス
*/
class LogEntry implements IMessageEditorController {

    final int tool;
    final IHttpRequestResponse requestResponse;
    final URL url;
    public boolean baseflag = false;

    /*
        コンストラクタ
    */
    LogEntry(int tool, IHttpRequestResponse requestResponse, URL url) {
        this.tool = tool;
        this.requestResponse = requestResponse;
        this.url = url;
    }
    

    /*
        リクエストの内容を返却
    */
    public RequestParamList reqres2header(IExtensionHelpers helper) {
        IRequestInfo reqinfo = helper.analyzeRequest(this.requestResponse);
        return new RequestParamList(reqinfo);
    }
    
    /*
        ログ比較用基ログの表示
    */
    public String tableLabel() {
        String ret = "";
        if (this.baseflag == true) {
            ret = "*";
        }
        return ret;
    }

    @Override
    public IHttpService getHttpService() {
        return requestResponse.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return requestResponse.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return requestResponse.getResponse();
    }
}

/*
    リクエストパラメータのリスト
*/
class RequestParamList {

    public List<RequestParam> params = new ArrayList();

    /*
        コンストラクタ
    */
    public RequestParamList(IRequestInfo reqinfo) {
        // header params
        List<String> headerStrings = reqinfo.getHeaders();
        for (String eachHeader : headerStrings) {
            String[] tempStrs = eachHeader.split(": ");
            String paramName = "";
            String paramValue = "";
            if (tempStrs.length >= 2) {
                paramName = tempStrs[0];
                tempStrs[0] = ""; // パラメータ名を空に
                for (String temp : tempStrs) {
                    paramValue += temp;
                }

                if ("Cookie".equals(paramName) == true) {
                    for (HttpCookie tempCookie : HttpCookie.parse(paramValue)) {
                        RequestParam param = new RequestParam(tempCookie.getName(), tempCookie.getValue());
                        this.params.add(param);
                    }
                } else {

                    RequestParam param = new RequestParam(paramName, paramValue);
                    this.params.add(param);
                }
            }
            else if (tempStrs.length == 1 && this.params.size() == 0) {
                // line 1
                String[] spaceSplits = tempStrs[0].split(" ");
                if (spaceSplits.length > 2) {
                    RequestParam param = new RequestParam("HEAD_URL", spaceSplits[1]);
                    this.params.add(param);
                }
            }
        }

        // GET and POST params
        for (IParameter reqparam : reqinfo.getParameters()) {
            RequestParam param = new RequestParam(reqparam.getName(), reqparam.getValue());
            this.params.add(param);
        }
    }

    /*
        パラメータ数を返却
    */
    public int getCount() {
        return this.params.size();
    }

    private HashMap<String, Integer> searched = new HashMap<>();

    /*
        指定のパラメータが存在するか
    */
    public int hasKey(String pname) {
        int ret = -1;
        int startindex = 0;

        for (int i = startindex; i < this.params.size(); i++) {
            RequestParam param = this.params.get(i);
            if (param.name.equals(pname) == true) {
                ret = i;
                searched.put(pname, new Integer(i));
                break;
            }
        }
        return ret;
    }
}

/*
    リクエストパラメータのクラス
*/
class RequestParam {

    public String name;
    public String value;

    /*
        コンストラクタ
    */
    public RequestParam(String name, String value) {
        this.name = name;
        this.value = value;
    }
}

class MyHttpService implements IHttpService
{
    private String url;
    private String host;
    private int port;
    private String protocol;

    MyHttpService(String argurl, String arghost, int argport, String argprotocol) {
        this.url = argurl;
        this.host = arghost;
        this.port = argport;
        this.protocol = argprotocol;
    }
    
    public String getUrl() {
        return this.url;
    }
    
    @Override
    public String getHost() {
        return this.host;
    }

    @Override
    public int getPort() {
        return this.port;
    }

    @Override
    public String getProtocol() {
        return this.protocol;
    }
    
    static MyHttpService createMyService(String argurl) {
        MyHttpService ret = null;
        
        Pattern purl = Pattern.compile("(https?):\\/\\/([\\w\\.\\-]+):?(\\d*)");
        Matcher murl = purl.matcher(argurl);
        if (murl.find() == true) {
            String protocol = murl.group(1);
            String host = murl.group(2).toLowerCase();
            String expport = murl.group(3);
            if (expport == null || expport.isEmpty()) {
                if (protocol.equals("http") == true){
                    expport = "80";
                } else if (protocol.equals("https") == true) {
                    expport = "443";
                }
            }
            int port = Integer.parseInt(expport);

            Pattern pfullurl = Pattern.compile("(https?:\\/\\/[\\w\\.\\-]+:?\\d*\\/\\S+)");
            Matcher mfullurl = pfullurl.matcher(argurl).reset();
            String url = protocol + "://" + host + ":" + expport;
            if (mfullurl.find() == true) {
                url = mfullurl.group(1);
            }
            ret = new MyHttpService(url, host, port, protocol);
        }
        
        return ret;
    }
}

class MyReqRes implements IHttpRequestResponse
{
    private IHttpService httpService;
    private String color;
    private String comment;
    private byte[] request;
    private byte[] response;

    MyReqRes(IHttpService hs) {
        this.httpService = hs;
    }

    @Override
    public byte[] getRequest() {
        return this.request;
    }

    @Override
    public void setRequest(byte[] message) {
        this.request = message;
    }

    @Override
    public byte[] getResponse() {
        return this.response;
    }

    @Override
    public void setResponse(byte[] message) {
        this.response = message;
    }

    @Override
    public String getComment() {
        return this.comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return this.color;
    }

    @Override
    public void setHighlight(String color) {
        this.color = color;
    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
    
}

