package burp;

import java.awt.Component;
import javax.swing.JPanel;

public class GuiTab implements ITab {
	IBurpExtenderCallbacks callbacks;
	JPanel tab;

	public GuiTab(IBurpExtenderCallbacks c) {
		callbacks = c;
		tab = new JPanel();
		callbacks.customizeUiComponent(tab);
	}

	@Override
	public String getTabCaption() {
		return BurpExtender.extensionName;
	}

	@Override
	public Component getUiComponent() {
		return this.tab;
	}
}
