/****************************************************************************
 * Copyright (C) 2013 ecsec GmbH.
 * All rights reserved.
 * Contact: ecsec GmbH (info@ecsec.de)
 *
 * This file is part of the Open eCard App.
 *
 * GNU General Public License Usage
 * This file may be used under the terms of the GNU General Public
 * License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of
 * this file. Please review the following information to ensure the
 * GNU General Public License version 3.0 requirements will be met:
 * http://www.gnu.org/copyleft/gpl.html.
 *
 * Other Usage
 * Alternatively, this file may be used in accordance with the terms
 * and conditions contained in a signed written agreement between
 * you and ecsec GmbH.
 *
 ***************************************************************************/

package org.openecard.richclient.gui.manage;

import org.openecard.richclient.gui.manage.addon.DefaultSettingsGroup;
import org.openecard.richclient.gui.manage.addon.DefaultSettingsPanel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Properties;
import javax.annotation.Nonnull;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.ListSelectionModel;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.openecard.addon.AddonManager;
import org.openecard.addon.AddonRegistry;
import org.openecard.addon.manifest.AddonSpecification;
import org.openecard.addon.manifest.AppExtensionSpecification;
import org.openecard.common.I18n;
import org.openecard.common.util.FileUtils;
import org.openecard.gui.graphics.GraphicsUtil;
import org.openecard.gui.graphics.OecLogoBgWhite;
import org.openecard.richclient.gui.manage.core.ConnectionSettingsAddon;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Dialog for the management of add-ons and builtin functionality.
 * The dialog hosts a sidebar where one can select the add-on or builtin item to display. The items are
 * {@link AddonPanel}s which are configured appropriately.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class ManagementDialog extends JDialog {

    private static final long serialVersionUID = 1L;
    private static final String LANGUAGE_CODE = System.getProperty("user.language");
    private static final Logger logger = LoggerFactory.getLogger(ManagementDialog.class);

    private static ManagementDialog runningDialog;

    private final I18n lang = I18n.getTranslation("addon");
    private final AddonManager manager;
    private final AddonRegistry cpReg;
    private final AddonRegistry fileReg;

    private JPanel selectionPanel;
    private JPanel contentPane;
    private JList coreList;
    private JList addonList;
    private JPanel addonPanel;
    private JLabel lastImage;

    /**
     * Creates a new instance of the dialog and displays it.
     * This method only permits a single instance, so this is the preferred way to open the dialog.
     *
     * @param manager
     */
    public static synchronized void showDialog(AddonManager manager) {
	if (runningDialog == null) {
	    ManagementDialog dialog = new ManagementDialog(manager);
	    dialog.addWindowListener(new WindowListener() {
		@Override
		public void windowOpened(WindowEvent e) {
		}
		@Override
		public void windowClosing(WindowEvent e) {
		}
		@Override
		public void windowClosed(WindowEvent e) {
		    ManagementDialog.runningDialog = null;
		}
		@Override
		public void windowIconified(WindowEvent e) {
		}
		@Override
		public void windowDeiconified(WindowEvent e) {
		}
		@Override
		public void windowActivated(WindowEvent e) {
		}
		@Override
		public void windowDeactivated(WindowEvent e) {
		}
	    });
	    dialog.setVisible(true);
	    runningDialog = dialog;
	} else {
	    // dialog already shown, bring to front
	    runningDialog.toFront();
	}
    }


    /**
     * Create a ManagementDialog instance.
     * The preferred way of opening this dialog is the {@link #showDialog()} function which also makes the dialog
     * visible and only permits one open instance at a time.
     *
     * @param manager
     */
    public ManagementDialog(AddonManager manager) {
	this.manager = manager;
	cpReg = manager.getBuiltinRegistry();
	fileReg = manager.getExternalRegistry();

	Image logo = GraphicsUtil.createImage(OecLogoBgWhite.class, 147, 147);
	setIconImage(logo);
	setTitle(lang.translationForKey("addon.title"));
	setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
	setMinimumSize(new Dimension(640, 420));
	setSize(730, 480);
	contentPane = new JPanel();
	contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
	contentPane.setLayout(new BorderLayout(0, 0));
	setContentPane(contentPane);

	addonPanel = new JPanel(new BorderLayout(), true);
	contentPane.add(addonPanel, BorderLayout.CENTER);

	JPanel selectionWrapper = new JPanel(new BorderLayout());
	contentPane.add(selectionWrapper, BorderLayout.WEST);
	selectionPanel = new JPanel();
	selectionWrapper.add(selectionPanel, BorderLayout.NORTH);
	selectionWrapper.add(Box.createHorizontalGlue(), BorderLayout.CENTER);

	GridBagLayout selectionLayout = new GridBagLayout();
	selectionLayout.rowHeights = new int[]{0, 0, 0, 0};
	selectionLayout.columnWeights = new double[]{1.0};
	selectionLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 1.0};
	selectionPanel.setLayout(selectionLayout);

	createCoreList();
	createAddonList();
	setupCoreList();
	setupAddonList();

	setLocationRelativeTo(null);
    }

    /**
     * Sets the logo in the main panel describing the current displayed add-on page.
     * This method should be called when the add-on page is replaced with another one.
     *
     * @param logo Image of the logo to display. Must be scaled to size 45x45.
     */
    public void setLogo(@Nonnull Image logo) {
	if (lastImage != null) {
	    selectionPanel.remove(lastImage);
	}
	lastImage = new JLabel(new ImageIcon(logo));
	GridBagConstraints labelConstraints = new GridBagConstraints();
	labelConstraints.insets = new Insets(5, 0, 6, 10);
	labelConstraints.anchor = GridBagConstraints.NORTH;
	labelConstraints.gridx = 0;
	labelConstraints.gridy = 0;
	selectionPanel.add(lastImage, labelConstraints);
	selectionPanel.revalidate();
	selectionPanel.repaint();
    }

    private void createCoreList() {
	JLabel label = new JLabel(lang.translationForKey("addon.list.core"));
	label.setFont(label.getFont().deriveFont(Font.BOLD));
	GridBagConstraints labelConstraints = new GridBagConstraints();
	labelConstraints.insets = new Insets(5, 0, 5, 10);
	labelConstraints.anchor = GridBagConstraints.NORTH;
	labelConstraints.gridx = 0;
	labelConstraints.gridy = 1;
	selectionPanel.add(label, labelConstraints);

	coreList = new JList();
	coreList.setFont(coreList.getFont().deriveFont(Font.PLAIN));
	coreList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
	GridBagConstraints coreListConstraints = new GridBagConstraints();
	coreListConstraints.fill = GridBagConstraints.HORIZONTAL;
	coreListConstraints.insets = new Insets(0, 5, 5, 10);
	coreListConstraints.anchor = GridBagConstraints.NORTH;
	coreListConstraints.gridx = 0;
	coreListConstraints.gridy = 2;

	AddonSelectionModel model = new AddonSelectionModel(this, addonPanel);
	coreList.setModel(model);
	coreList.addListSelectionListener(model);
	addWindowListener(model); // save current addon settings when closed
	// add addon panels
	model.addElement(lang.translationForKey("addon.list.core.connection"), new ConnectionSettingsAddon());

	// this assumes that all addons in the ClasspathRegistry are core addons
	// an ActionPanel for every addon that has one ore more AppExtensionActions will be added
	for (AddonSpecification desc : cpReg.listAddons()) {
	    ArrayList<AppExtensionSpecification> applicationActions = desc.getApplicationActions();
	    if (applicationActions.size() > 0) {
		String description  = desc.getLocalizedDescription(LANGUAGE_CODE);
		String name = desc.getLocalizedName(LANGUAGE_CODE);
		Image logo = loadLogo(desc.getLogo());
		JPanel actionPanel = createActionPanel(desc);
		AddonPanel nextPanel = new AddonPanel(actionPanel, name, description, logo);
		model.addElement(name, nextPanel);
	    }
	}

	selectionPanel.add(coreList, coreListConstraints);
    }

    /**
     * Creates an ActionPanel that has an ActionEntryPanel for every AppExtensionAction of the given addon.
     * 
     * @param desc AddonSpecification for the addon
     * @return the created ActionPanel
     */
    private ActionPanel createActionPanel(AddonSpecification desc) {
	ActionPanel actionPanel = new ActionPanel();
	for (AppExtensionSpecification action : desc.getApplicationActions()) {
	    ActionEntryPanel actionEntryPanel = new ActionEntryPanel(desc, action, manager);
	    actionPanel.addActionEntry(actionEntryPanel);
	}
	return actionPanel;
    }

    /**
     * Load the logo from the given path as {@link Image}.
     * 
     * @param logoPath path to the logo
     * @return the logo-{@link Image} if loading was successful, otherwise {@code null}
     */
    private static Image loadLogo(String logoPath) {
	if (logoPath == null || logoPath.isEmpty()) {
	    return null;
	}
	try {
	    InputStream in = FileUtils.resolveResourceAsStream(ManagementDialog.class, logoPath);
	    ImageIcon icon = new ImageIcon(FileUtils.toByteArray(in));
	    if (icon.getIconHeight() < 0 || icon.getIconWidth() < 0) {
		// supplied data was no image, btw the image API sucks
		return null;
	    }
	    return icon.getImage();
	} catch (IOException ex) {
	    // ignore and let the default decide
	    return null;
	}
    }

    private void createAddonList() {
	JLabel label = new JLabel(lang.translationForKey("addon.list.addon"));
	label.setFont(label.getFont().deriveFont(Font.BOLD));
	GridBagConstraints labelConstraints = new GridBagConstraints();
	labelConstraints.insets = new Insets(5, 0, 5, 10);
	labelConstraints.anchor = GridBagConstraints.NORTH;
	labelConstraints.gridx = 0;
	labelConstraints.gridy = 3;
	selectionPanel.add(label, labelConstraints);

	// TODO: remove this code
	//label.setVisible(false);

	addonList = new JList();
	addonList.setFont(addonList.getFont().deriveFont(Font.PLAIN));
	addonList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
	GridBagConstraints addonListConstraints = new GridBagConstraints();
	addonListConstraints.fill = GridBagConstraints.HORIZONTAL;
	addonListConstraints.insets = new Insets(0, 5, 5, 10);
	addonListConstraints.anchor = GridBagConstraints.NORTH;
	addonListConstraints.gridx = 0;
	addonListConstraints.gridy = 4;

	AddonSelectionModel model = new AddonSelectionModel(this, addonPanel);
	addonList.setModel(model);
	addonList.addListSelectionListener(model);
	addWindowListener(model); // save current addon settings when closed
	// add addon panels

	// this assumes that all addons in the FileRegistry are non core addons
	for (AddonSpecification desc : fileReg.listAddons()) {
	    String description = desc.getLocalizedDescription(LANGUAGE_CODE);
	    String name = desc.getLocalizedName(LANGUAGE_CODE);
	    Image logo = loadLogo(desc.getLogo());
	    Properties properties = new Properties();
	    try {
		File config = new File(FileUtils.getHomeConfigDir().getAbsolutePath() + File.separatorChar + "plugins"
			+ File.separatorChar + desc.getId() + ".properties");
		if (config.exists()) {
		    properties.load(new FileReader(config));
		} else {
		    logger.debug("A properties file for the addon with id {} does not yet exist", desc.getId());
		}
	    } catch (SecurityException e) {
		logger.error("Failed to load properties file for addon with id " + desc.getId(), e);
	    } catch (IOException e) {
		logger.error("Failed to load properties file for addon with id " + desc.getId(), e);
	    }
	    // TODO: what title should we set?
	    SettingsGroup settingsGroup = new DefaultSettingsGroup("", properties, desc);
	    AddonPanel nextPanel = new AddonPanel(new DefaultSettingsPanel(settingsGroup), name, description, logo);
	    model.addElement(name, nextPanel);
	}

	selectionPanel.add(addonList, addonListConstraints);
    }

    private void setupCoreList() {
	coreList.addListSelectionListener(new ClearSelectionListener(addonList));
	coreList.setSelectedIndex(0);
    }

    private void setupAddonList() {
	addonList.addListSelectionListener(new ClearSelectionListener(coreList));
    }

    private class ClearSelectionListener implements ListSelectionListener {
	private final JList otherList;

	public ClearSelectionListener(JList otherList) {
	    this.otherList = otherList;
	}
	@Override
	public void valueChanged(ListSelectionEvent e) {
	    Object source = e.getSource();
	    if (source instanceof JComponent) {
		JComponent component = (JComponent) source;
		// only do this when we have the focus
		if (! e.getValueIsAdjusting() && component.hasFocus()) {
		    otherList.clearSelection();
		}
	    }
	}
    }

}
