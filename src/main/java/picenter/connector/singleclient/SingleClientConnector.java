package picenter.connector.singleclient;

import picenter.connector.driver.Connector;
import picenter.connector.driver.DatabaseResults;
import picenter.connector.driver.Transaction;

class SingleClientConnector extends Connector {

    SingleClientConnector(String ip, String hostname, int port, String username, String password) throws Exception{
        super(ip, hostname, port, username, password);
    }

    public boolean connect() throws Exception{
        return super.connect();
    }

    public boolean isConnected(){
        return super.isConnected();
    }

    public String sendMessage(String msg) throws Exception{
        return super.sendMessage(msg);
    }

    public void logout() throws Exception{
        super.logout();
    }

    public DatabaseResults sendTransaction(Transaction transaction) throws Exception{
        return super.sendTransaction(transaction);
    }

}
