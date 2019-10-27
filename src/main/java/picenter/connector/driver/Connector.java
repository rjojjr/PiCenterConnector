package picenter.connector.driver;

import picenter.connector.common.debugging.Debugger;

import java.math.BigInteger;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;

public class Connector {

    private User user = null;

    private String ip = "", hostname = "", username = "";
    private BigInteger password;
    private int port = 0;
    private volatile ServerClient client = null;
    private DatabaseObjectFactory databaseObjectFactory = new DatabaseObjectFactory();
    private volatile AtomicBoolean loggedOn = new AtomicBoolean(false);
    private Keys keyManager;

    /**
     * @Depreciated
     * @param ip
     * @param hostname
     * @param port
     * @param username
     * @param password
     * @throws Exception
     */
    protected Connector(String ip, String hostname, int port, String username, String password) throws Exception {
        this.ip = ip;
        this.port = port;
        this.username = username;
        this.password = new BigInteger(CryptTools.getSHA256(password));
        this.hostname = hostname;
        keyManager = new Keys();
    }

    protected Connector(String ip, String hostname, int port) throws Exception {
        this.ip = ip;
        this.port = port;
        this.hostname = hostname;
        keyManager = new Keys();
    }

    protected boolean connect() throws Exception {
        if (!isConnected()) {
            client = new ServerClient();
            client.startConnection(hostname, ip, port);
            keyManager = new Keys();
            if (client.isConnected()) {
                try{
                    if(!keyManager.hasKey()){
                        keyManager.generateRSAKeys();
                        String key = client.sendMessage(Base64.getEncoder().encodeToString(keyManager.getPublicKey()));
                        if(!keyManager.decryptAESKey(Base64.getDecoder().decode(key))){
                            throw new Exception("Failed to complete handshake.");
                        }
                    }/*
                    try {

                        if(this.logon()){
                            //System.out.println("logged on");

                            loggedOn.set(true);
                            return true;
                        }else {
                            //System.out.println("not");
                            loggedOn.set(false);
                            return false;
                        }

                    } catch (Exception e) {
                        //System.out.println("Here");
                        //e.printStackTrace();
                        loggedOn.set(false);
                        throw e;
                    }
                    */
                }catch (Exception e){
                    System.err.println(e.getMessage());
                    e.printStackTrace();
                }
            }
        }
        return client.isConnected();
    }

     public String getUsername(){
        return username;
    }

    boolean logon() throws Exception {
        Transaction transaction = new Transaction(username, password);
        byte[] encrypted = keyManager.encryptAESRequest(databaseObjectFactory.databaseSerialFactory(transaction));
        if(encrypted == null){

            throw new Exception("Failed to encrypt request");
        }
        String input = sendMessage(Base64.getEncoder().encodeToString(encrypted));
        if(input == null){
            client = null;
            return false;
        }
        user = new User(null);// (User)databaseObjectFactory.databaseObjectFactory(Base64.getDecoder().decode(keyManager.decryptAESResponse(input)));
        return true;
    }

    /**
     * @Depreciated
     * @throws Exception
     */
    protected void logout() throws Exception {
        if(user != null){
            Transaction transaction = new Transaction();
            transaction.setOperation("LOGOFF");
            transaction.setUsername(username);
            transaction.setRequestTime(System.currentTimeMillis());
            sendMessage(Base64.getEncoder().encodeToString(keyManager.encryptAESRequest(databaseObjectFactory.databaseSerialFactory(transaction))));
            user = null;
        }
        if(client.isConnected()){
            client.stopConnection();
        }
        loggedOn.set(false);
    }

    protected DatabaseResults sendTransaction(Transaction transaction) throws Exception{
        if(isConnected()){
            Debugger.debug("Sent transaction");
            byte[] response = null;
            if((response = Base64.getDecoder().decode(keyManager.decryptAESResponse(sendMessage(Base64.getEncoder().encodeToString(keyManager.encryptAESRequest(databaseObjectFactory.databaseSerialFactory(transaction))))))) == null){
                client.stopConnection();
                client = null;
                Debugger.debug("Response is null");
                connect();
                sendTransaction(transaction);
            }
            if(response.equals("closed") || response == null){
                Debugger.debug("Response is closed");
                client.stopConnection();
                client = null;
                connect();
                sendTransaction(transaction);
            }
            try{
                Debugger.debug("Response = " + new String(response, "UTF-8"));
                return (DatabaseResults)databaseObjectFactory.databaseObjectFactory(response);
            }catch (Exception e){
                if(logon()){
                    transaction.setUsername(username);
                    return (DatabaseResults)databaseObjectFactory.databaseObjectFactory(Base64.getDecoder().decode(keyManager.decryptAESResponse(sendMessage(Base64.getEncoder().encodeToString(keyManager.encryptAESRequest(databaseObjectFactory.databaseSerialFactory(transaction)))))));
                }
                return null;
            }
        }else {
            if(logon()){
                transaction.setUsername(username);
                return (DatabaseResults)databaseObjectFactory.databaseObjectFactory(Base64.getDecoder().decode(keyManager.decryptAESResponse(sendMessage(Base64.getEncoder().encodeToString(keyManager.encryptAESRequest(databaseObjectFactory.databaseSerialFactory(transaction)))))));
            }
            return null;
        }
    }

    protected boolean isConnected() {
        if (client != null) {
            return client.isConnected();
        } else {
            return false;
        }
    }

    protected String sendMessage(String message) throws Exception {
        if (connect()) {
            return client.sendMessage(message);
        }
        return "Not connected";
    }

}
