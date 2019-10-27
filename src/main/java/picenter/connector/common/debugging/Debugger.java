package picenter.connector.common.debugging;

import picenter.connector.common.utilities.CalenderConverter;

public class Debugger {

    public static final boolean DEBUG = true;

    public static void debug(String log){
        if(DEBUG){
            System.out.println(log + " "
                    + CalenderConverter
                    .getMonthDayYearHourMinuteSecond(System.currentTimeMillis(), "/", "-")
            );
        }
    }

    public static void debug(String log, Exception e){
        if(DEBUG){
            String stackTrace = "";
            for(StackTraceElement trace : e.getStackTrace()){
                stackTrace+= System.lineSeparator() + trace.toString();
            }
            System.out.println(log + " "
                    + CalenderConverter
                        .getMonthDayYearHourMinuteSecond(System.currentTimeMillis(), "/", "-")
                    + stackTrace);
        }
    }

}
