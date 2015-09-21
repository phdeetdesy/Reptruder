/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import javax.swing.JFrame;

/**
 *
 * @author akurosu
 */
public class SessionHandlingTest implements ISessionHandlingAction, ActionListener {

    private BurpExtender parent = null;
    
    private JFrame rptrFrame = null;
    private Reptruder reptruder = null;
    
    private ArrayList<IHttpRequestResponse> tempRequests = new ArrayList<>();
    
    public SessionHandlingTest(BurpExtender prt) {
        this.parent = prt;
    }
    
    @Override
    public String getActionName() {
        return "SessionHandlingTest First";
    }

    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        try {
            if (macroItems != null) {
    //            this.parent.printStr(String.valueOf(macroItems.length));
                String creq = new String(currentRequest.getRequest(), "ISO-8859-1");
                this.parent.printStr(creq);
            } else {
                this.parent.printStr("no macro");
            }
        } catch (Exception e) {
            this.parent.printErr(e);
        }
    }
    
    public void setRequest(IHttpRequestResponse reqres) {
        this.tempRequests.add(reqres);
//                    this.parent.printStr(new String(reqres.getRequest()));
    }
    
    public void sendRequest() {
        try{
            if (this.tempRequests.size() > 0) {
                IHttpRequestResponse res = this.parent.callbacks.makeHttpRequest(
                        this.tempRequests.get(tempRequests.size()-1).getHttpService(),
                        this.tempRequests.get(tempRequests.size()-1).getRequest());
//                this.parent.printStr(new String(res.getResponse(), "ISO-8859-1"));
            }
        } catch (Exception e) {
            this.parent.printErr(e);
        }
    }

    @Override
    public void actionPerformed(ActionEvent ae) {
        try {
            if (this.reptruder == null) {
                this.rptrFrame = new JFrame();
                this.reptruder = new Reptruder(this.parent);
                this.rptrFrame.add(this.reptruder);
                this.rptrFrame.setSize(720, 500);
            }
            
            while (this.tempRequests.size() > 0) {
                IHttpRequestResponse reqres = this.tempRequests.remove(0);
                this.reptruder.addRequest(reqres);
            }
            
            if (this.rptrFrame.isVisible() == false) {
                this.rptrFrame.setVisible(true);
            }
            
            
            this.reptruder.validate();
            this.reptruder.repaint();
            
        } catch (Exception e) {
            this.parent.printErr(e);
        }
//        try{
//            this.sendRequest();
//        } catch (Exception e) {
//            this.parent.printErr(e);
//        }
    }
    
}
