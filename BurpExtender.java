package burp;

public class BurpExtender implements IBurpExtender {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("burp-hash");
    }
}
