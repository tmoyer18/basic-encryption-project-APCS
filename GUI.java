import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.security.SecureRandom;


//TODO: hybrid = encrypt with DES, then encrypt DES key with RSA, and do vis versa to decrypt
/**
 * Created by tmoyer18 on 5/7/17.
 */
public class GUI  {
    RSA rsa = new RSA(1024); //1024 bit key by default
    DES des = new DES();
    SecureRandom rnd = new SecureRandom();
    private JPanel rsaOnlyPanel = new JPanel(new GridLayout(4,2));
    private JPanel rsaVarPanel = new JPanel(new GridLayout(7,2));
    private JPanel desOnlyPanel = new JPanel(new GridLayout(4,2));
    private JPanel currentPanel = rsaOnlyPanel;
    private JPanel desVarPanel = new JPanel(new GridLayout(3,1));
    private JPanel hybridEncryptionPanel = new JPanel(new GridLayout(7,2));
    private boolean status = false;
    private boolean rsaVarMenuConstructed = false;
    private boolean hybridEncryptConstructed = false;
    private boolean desVarMenuConstructed = false;
    private boolean desEncryptConstructed = false;
    private boolean rsaEncryptConstructed = false;
    private boolean transferred = false;
    JFrame OverallEncryptionFrame = new JFrame("Encryption and Decryption");

    private BigInteger encodedInt;
    private ArrayList<BigInteger> encodedList = new ArrayList<>();
    public static void main(String[] args)
    {
        GUI gui = new GUI();

    }
    public GUI()
    {
        OverallEncryptionFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        drawRsaEncryptionAndMenuBar();
        rsaOnlyGui();
        rsaEncryptConstructed = true;

    }

    public void drawRsaEncryptionAndMenuBar()
    {
        JMenuBar bar = new JMenuBar();
        OverallEncryptionFrame.setJMenuBar(bar);
        JMenu RSA = new JMenu("RSA");
        JMenu DES = new JMenu("DES");
        JMenu Hybrid= new JMenu("Hybrid");

        JMenuItem rsaEncryptDecrypt = new JMenuItem("RSA encrypt/decrypt");
        rsaEncryptDecrypt.addActionListener(new ActionListener() {
            @Override
            //if not already constructed the construct,otherwise just switch panels
            public void actionPerformed(ActionEvent e) {
                if(rsaEncryptConstructed == false) {
                    switchPanels(rsaOnlyPanel, currentPanel);
                    currentPanel = rsaOnlyPanel;
                    rsaEncryptConstructed = true;
                }
                else if (currentPanel.equals(rsaOnlyPanel) == false)
                {
                    switchPanels(rsaOnlyPanel,currentPanel);
                    currentPanel = rsaOnlyPanel;
                }
            }
        });
        JMenuItem rsaVars = new JMenuItem("View RSA Variables");
        rsaVars.addActionListener(new ActionListener() {
            @Override
            //if not already constructed the construct,otherwise just switch panels

            public void actionPerformed(ActionEvent e) {
                //System.out.println(rsaVarMenuConstructed);
                if (rsaVarMenuConstructed == false) {
                    drawRsaVarMenu();
                    rsaVarMenuConstructed = true;
                    switchPanels(rsaOnlyPanel,currentPanel);
                    currentPanel = rsaOnlyPanel;
                }
                else if (currentPanel.equals(rsaVarPanel) == false)
                    switchPanels(rsaVarPanel,currentPanel);
                currentPanel = rsaVarPanel;
            }
        });

        JMenuItem desEncryptDecrypt = new JMenuItem("DES encrypt/decrypt");
        desEncryptDecrypt.addActionListener(new ActionListener() {
            @Override
            //if not already constructed the construct,otherwise just switch panels

            public void actionPerformed(ActionEvent e) {
                if(desEncryptConstructed == false)
                {
                    desOnlyGui();
                    desEncryptConstructed = true;
                    switchPanels(desOnlyPanel, currentPanel);
                    currentPanel = desOnlyPanel;
                }
                else if (currentPanel.equals(desOnlyPanel) == false)
                {
                    switchPanels(desOnlyPanel,currentPanel);
                    currentPanel = desOnlyPanel;
                }
            }
        });
        JMenuItem desVars = new JMenuItem("DES Vars");
        desVars.addActionListener(new ActionListener() {
            @Override
            //if not already constructed the construct,otherwise just switch panels

            public void actionPerformed(ActionEvent e) {
                if(desVarMenuConstructed == false) {
                    drawDESVarMenu();
                    desVarMenuConstructed = true;
                    switchPanels(desVarPanel,currentPanel);
                    currentPanel = desVarPanel;
                }
                else if (currentPanel.equals(desVarPanel) == false)
                {
                    switchPanels(desVarPanel,currentPanel);
                    currentPanel = desVarPanel;
                }
            }
        });
        JMenuItem hybridMenu = new JMenuItem("Hybrid Encryption/decryption");
        hybridMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(hybridEncryptConstructed == false)
                {
                    drawHybridEncrypt();
                    hybridEncryptConstructed = true;
                    switchPanels(hybridEncryptionPanel,currentPanel);
                    currentPanel = hybridEncryptionPanel;

                }
                else if (currentPanel.equals(hybridEncryptionPanel) == false)
                {
                    switchPanels(hybridEncryptionPanel,currentPanel);
                    currentPanel = hybridEncryptionPanel;
                }
            }
        });
        Hybrid.add(hybridMenu);
        RSA.add(rsaVars);
        RSA.add(rsaEncryptDecrypt);
        DES.add(desEncryptDecrypt);
        bar.add(RSA);
        bar.add(DES);
        DES.add(desVars);
        bar.add(Hybrid);
        OverallEncryptionFrame.setBounds(10,10,600,400);
    }

    private void drawHybridEncrypt() {
        JTextArea inputText = new JTextArea();
        JButton encryptDES = new JButton("Encrypt plaintext with DES");

        JTextArea desKey = new JTextArea(des.binaryToHex(des.getKey()));
        JButton encryptKey = new JButton("Encrypt DES key with RSA");
        JTextArea cipherText = new JTextArea();
        JTextArea encryptedKey = new JTextArea();
        JTextArea encryptedKeyTwo = new JTextArea();
        JTextArea decryptedKey = new JTextArea();
        JButton decryptKey = new JButton("Decrypt Key using RSA");
        JTextArea encryptedDES = new JTextArea();
        JTextArea decryptThisKey = new JTextArea();
        JButton decryptDES = new JButton("Decrypt ciphertext using DES");
        JTextArea decryptedText = new JTextArea();
        JButton clearValues = new JButton("Clear Values");
        JButton newKey = new JButton("Generate new Key");
        JScrollPane left1 = new JScrollPane(inputText);
        JScrollPane left2 = new JScrollPane(encryptDES);
        JScrollPane left3 = new JScrollPane(cipherText);
        JScrollPane left4 = new JScrollPane(desKey);
        JScrollPane left5 = new JScrollPane(encryptKey);
        JScrollPane left6 = new JScrollPane(encryptedKeyTwo);
        JScrollPane left7 = new JScrollPane(clearValues);
        JScrollPane right1 = new JScrollPane(encryptedKey);
        JScrollPane right2 = new JScrollPane(decryptKey);
        JScrollPane right3 = new JScrollPane(decryptedKey);
        JScrollPane right4 = new JScrollPane(encryptedDES);
        JScrollPane right5 = new JScrollPane(decryptDES);
        JScrollPane right6 = new JScrollPane(decryptedText);
        JScrollPane right7 = new JScrollPane(newKey);


        encryptDES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String result = des.encrypt(inputText.getText(), des.getKey());
                    encryptedDES.setText(result);
                    cipherText.setText(result);
                }
                catch(NullPointerException f)
                {
                    inputText.setText("Enter text");
                }
                catch(NumberFormatException g)
                {
                    inputText.setText("Enter text");
                }
            }
        });
        clearValues.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                cipherText.setText("");
                decryptedText.setText("");
                encryptedKey.setText("");
                encryptedKeyTwo.setText("");
                decryptedKey.setText("");
                encryptedDES.setText("");
                cipherText.setText("");
                inputText.setText("");






            }
        });
        newKey.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                des.setKey(des.generateRandomBinaryString(64));
                desKey.setText(des.binaryToHex(des.getKey()));
            }
        });
        encryptKey.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                encryptedKey.setText(rsa.callEncode(des.binaryToHex(des.getKey())).toString(16));
                encryptedKeyTwo.setText(encryptedKey.getText());
            }
        });

        decryptKey.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    BigInteger decimal = new BigInteger(encryptedKey.getText(), 16);
                    decryptedKey.setText(rsa.callDecode(decimal));
                }
                catch(NumberFormatException f)
                {

                }
            }
        });
        decryptDES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    decryptedText.setText(des.decrypt(encryptedDES.getText(), decryptedKey.getText()));
                }
                catch(NumberFormatException f)
                {

                }
            }
        });


        hybridEncryptionPanel.add(left1);
        hybridEncryptionPanel.add(right1);

        hybridEncryptionPanel.add(left2);
        hybridEncryptionPanel.add(right2);

        hybridEncryptionPanel.add(left3);
        hybridEncryptionPanel.add(right3);

        hybridEncryptionPanel.add(left4);
        hybridEncryptionPanel.add(right4);

        hybridEncryptionPanel.add(left5);
        hybridEncryptionPanel.add(right5);
        hybridEncryptionPanel.add(left6);
        hybridEncryptionPanel.add(right6);
        hybridEncryptionPanel.add(left7);
        hybridEncryptionPanel.add(right7);
        OverallEncryptionFrame.add(hybridEncryptionPanel);



    }



    public void desOnlyGui()
    {
        JTextArea text1Right = new JTextArea();
        JTextArea text2Right = new JTextArea();
        text2Right.setLineWrap(true);

        JTextArea text2Left = new JTextArea();

        text1Right.setLineWrap(true);
        text2Left.setLineWrap(true);
        text2Right.setLineWrap(true);
        JScrollPane bottom1 = new JScrollPane(text2Left);
        JScrollPane bottom2 = new JScrollPane(text2Right);


        JTextArea text1Left = new JTextArea();
        text1Left.setLineWrap(true);
        JScrollPane top1 = new JScrollPane(text1Left);
        JScrollPane top2 = new JScrollPane(text1Right);
        JButton button1 = new JButton("Encrypt using DES");
        button1.addActionListener(new ActionListener() {
            @Override
            //if not already constructed the construct,otherwise just switch panels

            public void actionPerformed(ActionEvent e) {
                String message = text1Left.getText();
                transferred = false;
                try {
                    String result = des.encrypt(message, des.getKey());
                    text2Left.setText(result);
                }
                catch(NumberFormatException f)
                {

                }




            }
        });

        JButton button2 = new JButton("Decrypt DES encrypted String");
        button2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //if not already constructed the construct,otherwise just switch panels

                String encodedMessage = text1Right.getText();
                String result = "";
                try {
                    if (transferred) {
                        try {
                            result = des.decrypt(encodedMessage, des.binaryToHex(des.getKey()));
                            text2Right.setText(result);
                        } catch (NullPointerException f) {

                        }
                    } else if (text1Right.getText().isEmpty() == false) {
                        try {
                            result = "" + des.decrypt(text1Right.getText(), des.binaryToHex(des.getKey()));

                            text2Right.setText("  " + result);
                        } catch (NumberFormatException f) {

                        }
                    } else {
                        text1Right.setText("ENTER CHARACTER OR TRANSFER VALUE");

                    }
                } catch (NumberFormatException f) {

                }
            }
        });
        JButton transfer = new JButton("Transfer DES Encrypted Value");
        transfer.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (text2Left.getText().length()>0) {
                    text1Right.setText("" + text2Left.getText());
                    transferred = true;
                }
            }
        });
        JButton clear = new JButton("Clear values");
        clear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                transferred=false;
                text1Left.setText("");
                text1Right.setText("");
                text2Left.setText("");
                text2Right.setText("");
            }
        });


        desOnlyPanel.add(top1);
        desOnlyPanel.add(top2);
        desOnlyPanel.add(button1);
        desOnlyPanel.add(button2);
        desOnlyPanel.add(bottom1);

        desOnlyPanel.add(bottom2);
        desOnlyPanel.add(transfer);
        desOnlyPanel.add(clear);
        OverallEncryptionFrame.add(desOnlyPanel);


        OverallEncryptionFrame.setVisible(true);
    }


    public void rsaOnlyGui()
    {


        //constructs main rsa encryption screen






        JTextArea text1Right = new JTextArea();
        JTextArea text2Right = new JTextArea();
        text2Right.setLineWrap(true);

        JTextArea text2Left = new JTextArea();

        text1Right.setLineWrap(true);
        text2Left.setLineWrap(true);
        text2Right.setLineWrap(true);
        JScrollPane bottom1 = new JScrollPane(text2Left);
        JScrollPane bottom2 = new JScrollPane(text2Right);


        JTextArea text1Left = new JTextArea();
        text1Left.setLineWrap(true);
        JScrollPane top1 = new JScrollPane(text1Left);
        JScrollPane top2 = new JScrollPane(text1Right);
        JButton button1 = new JButton("Encrypt using RSA");
        button1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String message = text1Left.getText();
                transferred = false;
                if(message.length() <=(rsa.getK()/16)&& message.length()>0) {
                    // check to see if message is smaller or equal to modulus
                    BigInteger n = rsa.callEncode(message);
                    encodedInt = n;
                    int binaryLength = encodedInt.toString(2).length();
                    String result = n.toString();
                    if(binaryLength>=rsa.getK()-7 && binaryLength<=rsa.getK())
                        //has at least 1 digit in the binary block of 1024 bits
                        text2Left.setText(result);
                    else
                    {
                        text2Left.setText("Variables not valid... please change in variable menu");
                    }


                }
                else if(message.length()>(rsa.getK()/16))
                {
                    text2Left.setText("Message too long!");
                }
                else
                {
                    text2Left.setText("Enter correctly formatted decimal number");
                }


            }
        });

        JButton button2 = new JButton("Decrypt using RSA");
        button2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String encodedMessage = text1Right.getText();
                String result = "";
                //
                if (transferred) {
                    // check to see if user click transferred button
                    try {
                        result = rsa.callDecode(encodedInt);
                        text2Right.setText(result);
                    }
                    catch(NullPointerException f)
                    {

                    }
                } else if (text1Right.getText().isEmpty() == false) {
                    //otherwise just decrypt the thing in the decrypt box
                    try {
                        result = "" + rsa.callDecode(new BigInteger(text1Right.getText()));

                        text2Right.setText("  " + result);
                    }
                    catch(NumberFormatException f)
                    {

                    }
                }

                else
                {
                    text1Right.setText("ENTER CHARACTER OR TRANSFER VALUE");

                }
            }
        });
        JButton transfer = new JButton("Transfer RSA Encrypted Value");
        transfer.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (text2Left.getText().isEmpty() == false) {
                    text1Right.setText("" + text2Left.getText());
                    transferred = true;
                }
            }
        });
        JButton clear = new JButton("Clear Values");
        clear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                transferred=false;
                text1Left.setText("");
                text1Right.setText("");
                text2Left.setText("");
                text2Right.setText("");
            }
        });
        rsaOnlyPanel.add(top1);
        rsaOnlyPanel.add(top2);
        rsaOnlyPanel.add(button1);
        rsaOnlyPanel.add(button2);
        rsaOnlyPanel.add(bottom1);

        rsaOnlyPanel.add(bottom2);
        rsaOnlyPanel.add(transfer);
        rsaOnlyPanel.add(clear);
        OverallEncryptionFrame.add(rsaOnlyPanel);


        OverallEncryptionFrame.setVisible(true);
        rsaOnlyPanel.setVisible(true);





    }

    public void drawDESVarMenu()
    {
        JTextArea keyTitle = new JTextArea("Key");
        keyTitle.setFont(keyTitle.getFont().deriveFont(24f));
        keyTitle.setEditable(false);

        JTextField keyArea = new JTextField(des.binaryToHex(des.getKey()));

        JButton changeKey = new JButton("Change key");
        changeKey.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //key has to be 64 bit binary string
                if(keyArea.getText().length()==64)
                {
                    des.setKey(des.binaryToHex(keyArea.getText()));
                }
                else
                {
                    keyArea.setText(des.getKey());
                }
            }
        });
        JScrollPane scrollingKeyArea = new JScrollPane(keyArea);
        desVarPanel.add(keyTitle);
        desVarPanel.add(scrollingKeyArea);
        desVarPanel.add(changeKey);
        OverallEncryptionFrame.add(desVarPanel);

    }

    public void drawRsaVarMenu()
    {
        // n,d,e,phi,p,q
        rsaVarMenuConstructed = true;
        JTextArea nTitle = new JTextArea("    N");
        nTitle.setFont(nTitle.getFont().deriveFont(24f));
        nTitle.setEditable(false);

        JTextArea eTitle = new JTextArea("    E");
        eTitle.setFont(eTitle.getFont().deriveFont(24f));
        eTitle.setEditable(false);
        JTextArea pTitle = new JTextArea("    P");
        pTitle.setFont(pTitle.getFont().deriveFont(24f));
        pTitle.setEditable(false);
        JTextArea phiTitle = new JTextArea("    Φ");
        phiTitle.setFont(phiTitle.getFont().deriveFont(24f));
        phiTitle.setEditable(false);
        JTextArea kTitle = new JTextArea("    K");
        kTitle.setFont(kTitle.getFont().deriveFont(24f));
        kTitle.setEditable(false);
        JTextArea qTitle = new JTextArea("    Q");
        qTitle.setFont(qTitle.getFont().deriveFont(24f));
        qTitle.setEditable(false);
        JTextArea dTitle = new JTextArea("    D");
        dTitle.setFont(dTitle.getFont().deriveFont(24f));
        dTitle.setEditable(false);
        JTextField nArea = new JTextField(rsa.getN().toString());
        JTextField kArea = new JTextField("" +rsa.getK());

        JTextField dArea = new JTextField(rsa.getD().toString());

        JTextField phiArea = new JTextField(rsa.getPhi().toString());
        JTextField eArea = new JTextField(rsa.getBigE().toString());
        JTextField pArea = new JTextField(rsa.getP().toString());
        JTextField qArea = new JTextField(rsa.getQ().toString());
        JScrollPane dPane = new JScrollPane(dArea);
        // insert T-Pain joke here
        JScrollPane qPane = new JScrollPane(qArea);
        JScrollPane pPane = new JScrollPane(pArea);
        JScrollPane kPane = new JScrollPane(kArea);
        JScrollPane phiPane = new JScrollPane(phiArea);
        JScrollPane ePane = new JScrollPane(eArea);
        JScrollPane nPane = new JScrollPane(nArea);
        JButton changeP = new JButton("Change P");
        changeP.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                rsa.setP(new BigInteger(pArea.getText()));
                rsa.calcN(rsa.getP(),rsa.getQ());
                rsa.calcPhi(rsa.getP(),rsa.getQ());
                nArea.setText("" + rsa.getN());
                phiArea.setText("" + rsa.getPhi());
            }
        });
        JButton changeQ = new JButton("Change Q");
        changeQ.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                rsa.setQ(new BigInteger(qArea.getText()));
                rsa.calcN(rsa.getP(),rsa.getQ());
                nArea.setText("" + rsa.getN());
            }
        });
        JButton changePhi = new JButton("Change Φ");
        changePhi.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                rsa.setPhi(new BigInteger(phiArea.getText()));
                rsa.calcD(rsa.getBigE(),rsa.getPhi());
                dArea.setText("" + rsa.getD());
            }
        });
        JButton changeN = new JButton("Change N");
        changeN.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                rsa.setN(new BigInteger(nArea.getText()));

            }
        });
        JButton changeE = new JButton("Change E (WARNING)");
        changeE.addActionListener(new ActionListener() {

            String dAreaText = "";
            @Override
            public void actionPerformed(ActionEvent e) {
                //check to see if new E value is invertible
                try {
                    rsa.setE(new BigInteger(eArea.getText()), eArea.getText());
                    rsa.calcD(rsa.getBigE(), rsa.getPhi());
                    dAreaText = rsa.getD().toString();

                }
                catch(ArithmeticException f) {
                    dAreaText = "Uninvertible E value - try choosing one of Fermat's numbers";
                }
                dArea.setText("" + dAreaText);

            }
        });
        JButton changeD = new JButton("Change D (WARNING)");
        changeD.addActionListener(new ActionListener() {
            String eAreaText = "";
            @Override
            public void actionPerformed(ActionEvent e) {
                // Check to see if new D is invertible
                try {
                    rsa.setD(new BigInteger(dArea.getText()));
                    rsa.calcE(rsa.getD(), rsa.getPhi());
                    eAreaText = rsa.getBigE().toString();
                }
                catch(ArithmeticException f)
                {
                    eAreaText = "Uninvertible D value in regards to Phi";
                }
                eArea.setText(eAreaText);
            }
        });
        JButton changeK = new JButton("Change K (divisible by 2)");
        changeK.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //check to see if key is at least 8 bits and divisible by 2
                if(Integer.parseInt(kArea.getText())>=8 && Integer.parseInt(kArea.getText()) % 2 == 0) {
                    RSA newRsa = new RSA(Integer.parseInt(kArea.getText()));
                    pArea.setText("" + rsa.getP());
                    qArea.setText("" + rsa.getQ());
                    nArea.setText("" + rsa.getN());
                    phiArea.setText("" + rsa.getPhi());
                    dArea.setText("" + rsa.getD());
                }

            }
        });
        rsaVarPanel.add(pTitle);
        rsaVarPanel.add(pPane);
        rsaVarPanel.add(changeP);
        rsaVarPanel.add(qTitle);
        rsaVarPanel.add(qPane);
        rsaVarPanel.add(changeQ);
        rsaVarPanel.add(phiTitle);
        rsaVarPanel.add(phiPane);
        rsaVarPanel.add(changePhi);
        rsaVarPanel.add(nTitle);
        rsaVarPanel.add(nPane);
        rsaVarPanel.add(changeN);
        rsaVarPanel.add(eTitle);
        rsaVarPanel.add(ePane);
        rsaVarPanel.add(changeE);
        rsaVarPanel.add(dTitle);
        rsaVarPanel.add(dPane);
        rsaVarPanel.add(changeD);
        rsaVarPanel.add(kTitle);
        rsaVarPanel.add(kPane);
        rsaVarPanel.add(changeK);
        OverallEncryptionFrame.add(rsaVarPanel);


        // implement getter and setter methods in RSA class
    }

    public ArrayList<BigInteger> getDecoded()
    {
        if(encodedList.size() > 0) {
            status = true;
            return encodedList;
        }

        else
        {
            status = false;

        }
        return encodedList;
    }
    public void switchPanels(JPanel switchToThis, JPanel makeThisInvisible)
    {

        makeThisInvisible.setVisible(false);
        switchToThis.setVisible(true);
        makeThisInvisible.setVisible(false);
    }




}
