package burp;

import java.awt.Color;
import java.awt.Component;
import javax.swing.JPanel;

public class GuiTab implements ITab {
	private Color burpGrey = new Color(146, 151, 161);
	private Color burpOrange = new Color(229, 137, 0);
	private Config config;
	private IBurpExtenderCallbacks callbacks;
	private JPanel tab;

	public GuiTab(BurpExtender b) {
		callbacks = b.getCallbacks();
		config = b.getConfig();

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
