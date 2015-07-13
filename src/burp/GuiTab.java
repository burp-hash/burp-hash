package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.PrintWriter;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;

public class GuiTab implements ITab {
	private JButton btnReinitDatabase;
	private JButton btnResetDefaults;
	private JButton btnSelectFile;
	private final Color burpGrey = new Color(146, 151, 161);
	private final Color burpOrange = new Color(229, 137, 0);
	private ButtonGroup buttonGroup1;
	private IBurpExtenderCallbacks callbacks;
	private JCheckBox chkMd5;
	private JCheckBox chkSha1;
	private JCheckBox chkSha224;
	private JCheckBox chkSha256;
	private JCheckBox chkSha384;
	private JCheckBox chkSha512;
	private Config config;
	private Database db;
	private JSeparator jSeparator1;
	private JSeparator jSeparator2;
	private JLabel lblBehavior;
	private JLabel lblExtensionName;
	private JLabel lblSelectAlgorithm;
	private JLabel lblSelectFile;
	private JPanel pnlAlgorithm;
	private JPanel pnlBehavior;
	private JPanel pnlBorder;
	private JPanel pnlBottomButtons;
	private JPanel pnlMain;
	private JPanel pnlSelectFile;
	private JRadioButton rbMatch;
	private JRadioButton rbReport;
	private PrintWriter stdOut;
	private JTextField txtFileName;

	public GuiTab(BurpExtender b) {
		callbacks = b.getCallbacks();
		config = b.getConfig();
		db = b.getDatabase();
		stdOut = b.getStdOut();

		initComponents();
		callbacks.customizeUiComponent(pnlMain);
	}

	private void btnReinitDatabaseActionPerformed(ActionEvent evt) {
		db.init();
		stdOut.println("Database Reinitialized.");
	}

	private void btnResetDefaultsActionPerformed(ActionEvent evt) {
		config.reset();
		loadConfig();
		stdOut.println("Configuration reset to defaults.");
	}

	private void btnSelectFileActionPerformed(ActionEvent evt) {
		File dbFile = selectDatabaseFile();
		if (dbFile != null) {
			config.databaseFilename = dbFile.getAbsolutePath();
			txtFileName.setText(config.databaseFilename);
			db.changeFile();
		}
	}

	private void chkMd5ActionPerformed(ActionEvent evt) {
		config.isMd5Enabled = !config.isMd5Enabled;
	}

	private void chkSha1ActionPerformed(ActionEvent evt) {
		config.isSha1Enabled = !config.isSha1Enabled;
	}

	private void chkSha224ActionPerformed(ActionEvent evt) {
		config.isSha224Enabled = !config.isSha224Enabled;
	}

	private void chkSha256ActionPerformed(ActionEvent evt) {
		config.isSha256Enabled = !config.isSha256Enabled;
	}

	private void chkSha384ActionPerformed(ActionEvent evt) {
		config.isSha384Enabled = !config.isSha384Enabled;
	}

	private void chkSha512ActionPerformed(ActionEvent evt) {
		config.isSha512Enabled = !config.isSha512Enabled;
	}

	@Override
	public String getTabCaption() {
		return BurpExtender.extensionName;
	}

	@Override
	public Component getUiComponent() {
		return pnlMain;
	}

	private void initComponents() {
		buttonGroup1 = new ButtonGroup();
		pnlMain = new JPanel();
		pnlBorder = new JPanel();
		lblExtensionName = new JLabel();
		pnlAlgorithm = new JPanel();
		lblSelectAlgorithm = new JLabel();
		chkMd5 = new JCheckBox();
		chkSha1 = new JCheckBox();
		chkSha256 = new JCheckBox();
		chkSha512 = new JCheckBox();
		chkSha384 = new JCheckBox();
		chkSha224 = new JCheckBox();
		jSeparator1 = new JSeparator();
		pnlBehavior = new JPanel();
		rbReport = new JRadioButton();
		rbMatch = new JRadioButton();
		lblBehavior = new JLabel();
		jSeparator2 = new JSeparator();
		pnlSelectFile = new JPanel();
		btnSelectFile = new JButton();
		txtFileName = new JTextField();
		lblSelectFile = new JLabel();
		pnlBottomButtons = new JPanel();
		btnReinitDatabase = new JButton();
		btnResetDefaults = new JButton();

		loadConfig();

		pnlBorder.setBorder(BorderFactory.createLineBorder(burpGrey));
		pnlBorder.setLocation(new Point(1, 1));

		lblExtensionName.setFont(lblExtensionName.getFont().deriveFont(
				lblExtensionName.getFont().getStyle() | Font.BOLD, lblExtensionName.getFont().getSize() + 3));
		lblExtensionName.setForeground(burpOrange);
		lblExtensionName.setText(BurpExtender.extensionName);

		lblSelectAlgorithm.setText("Select hash algorithms to enable.");

		chkMd5.setText("MD5");
		chkMd5.addActionListener(evt -> {
			chkMd5ActionPerformed(evt);
		});

		chkSha1.setText("SHA-1");
		chkSha1.addActionListener(evt -> {
			chkSha1ActionPerformed(evt);
		});

		chkSha256.setText("SHA-256");
		chkSha256.addActionListener(evt -> {
			chkSha256ActionPerformed(evt);
		});

		chkSha224.setText("SHA-224");
		chkSha224.addActionListener(evt -> {
			chkSha224ActionPerformed(evt);
		});

		chkSha384.setText("SHA-384");
		chkSha384.addActionListener(evt -> {
			chkSha384ActionPerformed(evt);
		});

		chkSha512.setText("SHA-512");
		chkSha512.addActionListener(evt -> {
			chkSha512ActionPerformed(evt);
		});

		GroupLayout pnlAlgorithmLayout = new GroupLayout(pnlAlgorithm);
		pnlAlgorithm.setLayout(pnlAlgorithmLayout);
		pnlAlgorithmLayout
				.setHorizontalGroup(pnlAlgorithmLayout
						.createParallelGroup(Alignment.LEADING)
						.addGroup(
								pnlAlgorithmLayout
										.createSequentialGroup()
										.addContainerGap()
										.addGroup(
												pnlAlgorithmLayout
														.createParallelGroup(
																Alignment.LEADING)
														.addComponent(
																lblSelectAlgorithm)
														.addGroup(
																pnlAlgorithmLayout
																		.createSequentialGroup()
																		.addGroup(
																				pnlAlgorithmLayout
																						.createParallelGroup(
																								Alignment.LEADING)
																						.addComponent(
																								chkSha256)
																						.addComponent(
																								chkSha1)
																						.addComponent(
																								chkMd5))
																		.addGap(18,
																				18,
																				18)
																		.addGroup(
																				pnlAlgorithmLayout
																						.createParallelGroup(
																								Alignment.LEADING)
																						.addComponent(
																								chkSha224)
																						.addComponent(
																								chkSha384)
																						.addComponent(
																								chkSha512))))
										.addContainerGap(
												GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)));
		pnlAlgorithmLayout.setVerticalGroup(pnlAlgorithmLayout
				.createParallelGroup(Alignment.LEADING).addGroup(
						pnlAlgorithmLayout
								.createSequentialGroup()
								.addContainerGap()
								.addComponent(lblSelectAlgorithm)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addGroup(
										pnlAlgorithmLayout
												.createParallelGroup(
														Alignment.BASELINE)
												.addComponent(chkMd5)
												.addComponent(chkSha224))
								.addPreferredGap(ComponentPlacement.RELATED)
								.addGroup(
										pnlAlgorithmLayout
												.createParallelGroup(
														Alignment.BASELINE)
												.addComponent(chkSha1)
												.addComponent(chkSha384))
								.addPreferredGap(ComponentPlacement.RELATED)
								.addGroup(
										pnlAlgorithmLayout
												.createParallelGroup(
														Alignment.BASELINE)
												.addComponent(chkSha256)
												.addComponent(chkSha512))
								.addContainerGap(GroupLayout.DEFAULT_SIZE,
										Short.MAX_VALUE)));

		buttonGroup1.add(rbReport);
		rbReport.setText("Report Only");
		rbReport.addActionListener(evt -> {
				rbReportActionPerformed(evt);
		});

		buttonGroup1.add(rbMatch);
		rbMatch.setText("Match and Report Hashes");
		rbMatch.addActionListener(evt -> {
				rbMatchActionPerformed(evt);
		});

		lblBehavior.setText("Select hashing behavior.");

		GroupLayout pnlBehaviorLayout = new GroupLayout(pnlBehavior);
		pnlBehavior.setLayout(pnlBehaviorLayout);
		pnlBehaviorLayout
				.setHorizontalGroup(pnlBehaviorLayout
						.createParallelGroup(Alignment.LEADING)
						.addGroup(
								pnlBehaviorLayout
										.createSequentialGroup()
										.addContainerGap()
										.addGroup(
												pnlBehaviorLayout
														.createParallelGroup(
																Alignment.LEADING)
														.addComponent(
																lblBehavior)
														.addGroup(
																pnlBehaviorLayout
																		.createSequentialGroup()
																		.addComponent(
																				rbMatch)
																		.addPreferredGap(
																				ComponentPlacement.UNRELATED)
																		.addComponent(
																				rbReport)))
										.addContainerGap(
												GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)));
		pnlBehaviorLayout.setVerticalGroup(pnlBehaviorLayout
				.createParallelGroup(Alignment.LEADING).addGroup(
						Alignment.TRAILING,
						pnlBehaviorLayout
								.createSequentialGroup()
								.addContainerGap()
								.addComponent(lblBehavior)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addGroup(
										pnlBehaviorLayout
												.createParallelGroup(
														Alignment.BASELINE)
												.addComponent(rbMatch)
												.addComponent(rbReport))
								.addContainerGap(GroupLayout.DEFAULT_SIZE,
										Short.MAX_VALUE)));

		btnSelectFile.setText("Select file ...");
		btnSelectFile.addActionListener(evt -> {
				btnSelectFileActionPerformed(evt);
		});

		txtFileName.setEnabled(false);
		txtFileName.addActionListener(evt -> {
				txtFileNameActionPerformed(evt);
		});

		lblSelectFile
				.setText("Select the output file to which hashes and parameters will be saved.");

		GroupLayout pnlSelectFileLayout = new GroupLayout(pnlSelectFile);
		pnlSelectFile.setLayout(pnlSelectFileLayout);
		pnlSelectFileLayout
				.setHorizontalGroup(pnlSelectFileLayout
						.createParallelGroup(Alignment.LEADING)
						.addGroup(
								pnlSelectFileLayout
										.createSequentialGroup()
										.addContainerGap()
										.addGroup(
												pnlSelectFileLayout
														.createParallelGroup(
																Alignment.LEADING)
														.addGroup(
																pnlSelectFileLayout
																		.createSequentialGroup()
																		.addComponent(
																				btnSelectFile)
																		.addPreferredGap(
																				ComponentPlacement.RELATED)
																		.addComponent(
																				txtFileName,
																				GroupLayout.PREFERRED_SIZE,
																				320,
																				GroupLayout.PREFERRED_SIZE))
														.addComponent(
																lblSelectFile))
										.addContainerGap(172, Short.MAX_VALUE)));
		pnlSelectFileLayout
				.setVerticalGroup(pnlSelectFileLayout
						.createParallelGroup(Alignment.LEADING)
						.addGroup(
								pnlSelectFileLayout
										.createSequentialGroup()
										.addContainerGap()
										.addComponent(lblSelectFile)
										.addPreferredGap(
												ComponentPlacement.RELATED)
										.addGroup(
												pnlSelectFileLayout
														.createParallelGroup(
																Alignment.BASELINE)
														.addComponent(
																btnSelectFile)
														.addComponent(
																txtFileName,
																GroupLayout.PREFERRED_SIZE,
																GroupLayout.DEFAULT_SIZE,
																GroupLayout.PREFERRED_SIZE))
										.addContainerGap(
												GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)));

		btnReinitDatabase.setText("Reinitialize Database");
		btnReinitDatabase.addActionListener(evt -> {
				btnReinitDatabaseActionPerformed(evt);
		});

		btnResetDefaults.setText("Reset Defaults");
		btnResetDefaults.addActionListener(evt -> {
				btnResetDefaultsActionPerformed(evt);
		});

		GroupLayout pnlBottomButtonsLayout = new GroupLayout(pnlBottomButtons);
		pnlBottomButtons.setLayout(pnlBottomButtonsLayout);
		pnlBottomButtonsLayout.setHorizontalGroup(pnlBottomButtonsLayout
				.createParallelGroup(Alignment.LEADING).addGroup(
						pnlBottomButtonsLayout
								.createSequentialGroup()
								.addContainerGap()
								.addComponent(btnResetDefaults)
								.addGap(18, 18, 18)
								.addComponent(btnReinitDatabase)
								.addContainerGap(GroupLayout.DEFAULT_SIZE,
										Short.MAX_VALUE)));
		pnlBottomButtonsLayout
				.setVerticalGroup(pnlBottomButtonsLayout
						.createParallelGroup(Alignment.LEADING)
						.addGroup(
								Alignment.TRAILING,
								pnlBottomButtonsLayout
										.createSequentialGroup()
										.addContainerGap(
												GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)
										.addGroup(
												pnlBottomButtonsLayout
														.createParallelGroup(
																Alignment.BASELINE)
														.addComponent(
																btnResetDefaults)
														.addComponent(
																btnReinitDatabase))
										.addContainerGap()));

		GroupLayout pnlBorderLayout = new GroupLayout(pnlBorder);
		pnlBorder.setLayout(pnlBorderLayout);
		pnlBorderLayout
				.setHorizontalGroup(pnlBorderLayout
						.createParallelGroup(Alignment.LEADING)
						.addGroup(
								Alignment.TRAILING,
								pnlBorderLayout
										.createSequentialGroup()
										.addContainerGap()
										.addGroup(
												pnlBorderLayout
														.createParallelGroup(
																Alignment.TRAILING)
														.addComponent(
																pnlBottomButtons,
																GroupLayout.DEFAULT_SIZE,
																GroupLayout.DEFAULT_SIZE,
																Short.MAX_VALUE)
														.addComponent(
																pnlAlgorithm,
																GroupLayout.DEFAULT_SIZE,
																GroupLayout.DEFAULT_SIZE,
																Short.MAX_VALUE)
														.addComponent(
																jSeparator1,
																Alignment.LEADING)
														.addComponent(
																pnlBehavior,
																GroupLayout.DEFAULT_SIZE,
																GroupLayout.DEFAULT_SIZE,
																Short.MAX_VALUE)
														.addComponent(
																jSeparator2,
																Alignment.LEADING)
														.addComponent(
																pnlSelectFile,
																Alignment.LEADING,
																GroupLayout.DEFAULT_SIZE,
																GroupLayout.DEFAULT_SIZE,
																Short.MAX_VALUE)
														.addGroup(
																Alignment.LEADING,
																pnlBorderLayout
																		.createSequentialGroup()
																		.addComponent(
																				lblExtensionName)
																		.addGap(0,
																				0,
																				Short.MAX_VALUE)))
										.addContainerGap()));
		pnlBorderLayout.setVerticalGroup(pnlBorderLayout.createParallelGroup(
				Alignment.LEADING).addGroup(
				pnlBorderLayout
						.createSequentialGroup()
						.addContainerGap()
						.addComponent(lblExtensionName)
						.addGap(18, 18, 18)
						.addComponent(pnlAlgorithm, GroupLayout.PREFERRED_SIZE,
								GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(ComponentPlacement.RELATED)
						.addComponent(jSeparator1, GroupLayout.PREFERRED_SIZE,
								GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(ComponentPlacement.RELATED)
						.addComponent(pnlBehavior, GroupLayout.PREFERRED_SIZE,
								GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(ComponentPlacement.RELATED)
						.addComponent(jSeparator2, GroupLayout.PREFERRED_SIZE,
								GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(ComponentPlacement.RELATED)
						.addComponent(pnlSelectFile,
								GroupLayout.PREFERRED_SIZE,
								GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(ComponentPlacement.RELATED, 60,
								Short.MAX_VALUE)
						.addComponent(pnlBottomButtons,
								GroupLayout.PREFERRED_SIZE,
								GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE).addContainerGap()));

		GroupLayout pnlMainLayout = new GroupLayout(pnlMain);
		pnlMain.setLayout(pnlMainLayout);
		pnlMainLayout.setHorizontalGroup(pnlMainLayout.createParallelGroup(
				Alignment.LEADING).addGroup(
				pnlMainLayout
						.createSequentialGroup()
						.addContainerGap()
						.addComponent(pnlBorder, GroupLayout.DEFAULT_SIZE,
								GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addContainerGap()));
		pnlMainLayout.setVerticalGroup(pnlMainLayout.createParallelGroup(
				Alignment.LEADING).addGroup(
				pnlMainLayout
						.createSequentialGroup()
						.addContainerGap()
						.addComponent(pnlBorder, GroupLayout.DEFAULT_SIZE,
								GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addContainerGap()));

	}

	private void loadConfig() {
		chkMd5.setSelected(config.isMd5Enabled);
		chkSha1.setSelected(config.isSha1Enabled);
		chkSha224.setSelected(config.isSha224Enabled);
		chkSha256.setSelected(config.isSha256Enabled);
		chkSha384.setSelected(config.isSha384Enabled);
		chkSha512.setSelected(config.isSha512Enabled);
		rbMatch.setSelected(!config.reportHashesOnly);
		rbReport.setSelected(config.reportHashesOnly);
		txtFileName.setText(config.databaseFilename);
	}

	private void rbMatchActionPerformed(ActionEvent evt) {
		config.reportHashesOnly = false;
	}

	private void rbReportActionPerformed(ActionEvent evt) {
		config.reportHashesOnly = true;
	}

	private File selectDatabaseFile() {
		JFileChooser fc = new JFileChooser();
		fc.setSelectedFile(new File(config.databaseFilename));
		if (fc.showOpenDialog(pnlMain) == JFileChooser.APPROVE_OPTION) {
			return fc.getSelectedFile();
		}
		return null;
	}

	private void txtFileNameActionPerformed(ActionEvent evt) {
		btnSelectFileActionPerformed(evt);
	}
}
