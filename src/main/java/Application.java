import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Timer;
import java.util.TimerTask;

public class Application {


    public static void main(String[] args) {
        Timer time = new Timer();
        GeneratePassword gp = new GeneratePassword();
        gp.run();
        time.schedule(gp, 30000 - (System.currentTimeMillis() % 30000), 30000);
    }

    static class GeneratePassword extends TimerTask {

        PasscodeGenerator pg;

        GeneratePassword() {
            pg = new PasscodeGenerator();
        }

        @Override
        public void run() {
            try {
                String passcode = pg.getPasscode("c4yl qurb mw23 6dr5 qev5 nrd4 udp3 eowk");
                System.out.println("password: " + passcode);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }
    }
}
