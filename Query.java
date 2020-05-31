package flightapp;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.*;
import java.util.*;


/**
 * Runs queries against a back-end database
 */
public class Query {
  // DB Connection
  private Connection conn;

  // Password hashing parameter constants
  private static final int HASH_STRENGTH = 65536;
  private static final int KEY_LENGTH = 128;

  // Canned queries
  private static final String CHECK_FLIGHT_CAPACITY = "SELECT capacity FROM Flights WHERE fid = ?";
  private PreparedStatement checkFlightCapacityStatement;

  // For check dangling
  private static final String TRANCOUNT_SQL = "SELECT @@TRANCOUNT AS tran_count";
  private PreparedStatement tranCountStatement;


  // TODO: YOUR CODE HERE
  // 1. username
  private String login_user;
  // 2. Search Result
  private List<Flight[]> IterTable;
  // 3. Reservations for RID
  private HashMap<Integer,Flight[]> Reservations;
  // 4. RID pay or not pay
  private HashMap<Integer,Boolean> Payment;
  private static final String CLEAR_TABLE = "truncate Table Users";
  private static final String CLEAR_TABLE2 = "truncate Table Reservation";
  private static final String LOGIN_SQL = "SELECT * From Users as u WHERE u.username = ?";
  private PreparedStatement loginStatement;
  private static final String CREATE_INFO = "INSERT INTO Users VALUES(?,?,?,?)";
  private PreparedStatement createStatement;
  private PreparedStatement beginTxnStmt;
  private PreparedStatement commitTxnStmt;
  private PreparedStatement abortTxnStmt;


  //TODO : CREATE Function
  public void Create(String username, String password, Integer balance) throws  SQLException, IOException{


  }
  public Query() throws SQLException, IOException {
    this(null, null, null, null);
  }

  protected Query(String serverURL, String dbName, String adminName, String password)
          throws SQLException, IOException {
    conn = serverURL == null ? openConnectionFromDbConn()
            : openConnectionFromCredential(serverURL, dbName, adminName, password);

    prepareStatements();
  }

  /**
   * Return a connecion by using dbconn.properties file
   *
   * @throws SQLException
   * @throws IOException
   */
  public static Connection openConnectionFromDbConn() throws SQLException, IOException {
    // Connect to the database with the provided connection configuration
    Properties configProps = new Properties();
    configProps.load(new FileInputStream("dbconn.properties"));
    String serverURL = configProps.getProperty("flightapp.server_url");
    String dbName = configProps.getProperty("flightapp.database_name");
    String adminName = configProps.getProperty("flightapp.username");
    String password = configProps.getProperty("flightapp.password");
    return openConnectionFromCredential(serverURL, dbName, adminName, password);
  }

  /**
   * Return a connecion by using the provided parameter.
   *
   * @param serverURL example: example.database.widows.net
   * @param dbName    database name
   * @param adminName username to login server
   * @param password  password to login server
   *
   * @throws SQLException
   */
  protected static Connection openConnectionFromCredential(String serverURL, String dbName,
                                                           String adminName, String password) throws SQLException {
    String connectionUrl =
            String.format("jdbc:sqlserver://%s:1433;databaseName=%s;user=%s;password=%s", serverURL,
                    dbName, adminName, password);
    Connection conn = DriverManager.getConnection(connectionUrl);

    // By default, automatically commit after each statement
    conn.setAutoCommit(true);

    // By default, set the transaction isolation level to serializable
    conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);

    return conn;
  }

  /**
   * Get underlying connection
   */
  public Connection getConnection() {
    return conn;
  }

  /**
   * Closes the application-to-database connection
   */
  public void closeConnection() throws SQLException {
    conn.close();
  }

  /**
   * Clear the data in any custom tables created.
   *
   * WARNING! Do not drop any tables and do not clear the flights table.
   */
  public void clearTables() {
    try {
      // TODO: YOUR CODE HERE
      Statement st = conn.createStatement();
      st.execute(CLEAR_TABLE);
      st.execute(CLEAR_TABLE2);

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  /*
   * prepare all the SQL statements in this method.
   */
  private void prepareStatements() throws SQLException {
    beginTxnStmt = conn.prepareStatement(
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE; BEGIN TRANSACTION;");
    commitTxnStmt = conn.prepareStatement("COMMIT TRANSACTION");
    abortTxnStmt = conn.prepareStatement("ROLLBACK TRANSACTION");
    checkFlightCapacityStatement = conn.prepareStatement(CHECK_FLIGHT_CAPACITY);
    tranCountStatement = conn.prepareStatement(TRANCOUNT_SQL);
    loginStatement = conn.prepareStatement(LOGIN_SQL);
   createStatement = conn.prepareStatement(CREATE_INFO);


    // TODO: YOUR CODE HERE
    Reservations=new HashMap<>();
    IterTable=new ArrayList<>();
    Payment=new HashMap<>();

  }
  private static boolean validatePassword(String originalPassword,byte[] salt, byte[] hash) throws NoSuchAlgorithmException, InvalidKeySpecException
  {
    PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, HASH_STRENGTH, hash.length * 8);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] testHash = skf.generateSecret(spec).getEncoded();

    int diff = hash.length ^ testHash.length;
    for(int i = 0; i < hash.length && i < testHash.length; i++)
    {
      diff |= hash[i] ^ testHash[i];
    }
    return diff == 0;
  }

  private static ArrayList<byte[]> generateStorngPasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
  {

    char[] chars = password.toCharArray();
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    ArrayList<byte[]>result=  new ArrayList<>();
    PBEKeySpec spec = new PBEKeySpec(chars, salt, HASH_STRENGTH, 64 * 8);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] hash = skf.generateSecret(spec).getEncoded();
    result.add(salt);
    result.add(hash);
    return result;
  }
  /**
   * Takes a user's username and password and attempts to log the user in.
   *
   * @param username user's username
   * @param password user's password
   *
   * @return If someone has already logged in, then return "User already logged in\n" For all other
   *         errors, return "Login failed\n". Otherwise, return "Logged in as [username]\n".
   */
  public String transaction_login(String username, String password) {


    // TODO: YOUR CODE HERE
    if (login_user!=null) return "User already logged in\n";
    try{
      loginStatement.clearParameters();
      loginStatement.setString(1,username);
      ResultSet salt_name=loginStatement.executeQuery();
      ResultSetMetaData R=salt_name.getMetaData();
      int cn=R.getColumnCount();
      byte[] realsalt = null;
      byte[] realhash=null;
      while (salt_name.next()){
        realsalt=salt_name.getBytes(3);
        realhash=salt_name.getBytes(2);
      }
      if (realsalt==null|| realhash==null) return "Login failed\n";

      if (!validatePassword(password,realsalt,realhash)){
        return "Login failed\n";
      }

    }
    catch (SQLException o){
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    } finally {
      checkDanglingTransaction();
    }
    login_user=username;
    return "Logged in as "+username+"\n";
  }


  /**
   * Implement the create user function.
   *
   * @param username   new user's username. User names are unique the system.
   * @param password   new user's password.
   * @param initAmount initial amount to deposit into the user's account, should be >= 0 (failure
   *                   otherwise).
   *
   * @return either "Created user {@code username}\n" or "Failed to create user\n" if failed.
   */
  public String transaction_createCustomer(String username, String password, int initAmount) {
    try {
      // TODO: YOUR CODE HERE
      if (initAmount<0) return "Failed to create user\n";
      if (username.length()>20) return "Failed to create user\n";
      beginTransaction();
      username=username.toLowerCase();
      Statement st=conn.createStatement();
      String query="Select * from Users WITH (UPDLOCK)\n";
      ResultSet result=st.executeQuery(query);
      List<String> exist=new ArrayList<>();
      while(result.next()){
        exist.add(result.getString("username"));
      }
      if (exist.contains(username))
      {rollbackTransaction();
        return "Failed to create user\n";}
      // Generate a random cryptographic salt
      SecureRandom random = new SecureRandom();
      byte[] salt = new byte[16];

      random.nextBytes(salt);

      // Specify the hash parameters
      KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);

      // Generate the hash
      SecretKeyFactory factory = null;
      byte[] hash = null;
      try {
        factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        hash = factory.generateSecret(spec).getEncoded();

      } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
        throw new IllegalStateException();}

      // store password
      createStatement.clearParameters();
      createStatement.setString(1, username);
      createStatement.setBytes(2, hash);
      createStatement.setBytes(3, salt);
      createStatement.setInt(4, initAmount);
      createStatement.executeUpdate();
      commitTransaction();
    } catch (SQLException throwables) {
      throwables.printStackTrace();
    } finally {
      checkDanglingTransaction();
    }
    return "Created user "+username+"\n" ;
  }

  /**
   * Implement the search function.
   *
   * Searches for flights from the given origin city to the given destination city, on the given day
   * of the month. If {@code directFlight} is true, it only searches for direct flights, otherwise
   * is searches for direct flights and flights with two "hops." Only searches for up to the number
   * of itineraries given by {@code numberOfItineraries}.
   *
   * The results are sorted based on total flight time.
   *
   * @param originCity
   * @param destinationCity
   * @param directFlight        if true, then only search for direct flights, otherwise include
   *                            indirect flights as well
   * @param dayOfMonth
   * @param numberOfItineraries number of itineraries to return
   *
   * @return If no itineraries were found, return "No flights match your selection\n". If an error
   *         occurs, then return "Failed to search\n".
   *
   *         Otherwise, the sorted itineraries printed in the following format:
   *
   *         Itinerary [itinerary number]: [number of flights] flight(s), [total flight time]
   *         minutes\n [first flight in itinerary]\n ... [last flight in itinerary]\n
   *
   *         Each flight should be printed using the same format as in the {@code Flight} class.
   *         Itinerary numbers in each search should always start from 0 and increase by 1.
   *
   * @see Flight#toString()
   */

  public String transaction_search(String originCity, String destinationCity, boolean directFlight,
                                   int dayOfMonth, int numberOfItineraries) {
    int time=0;

    try {
      // WARNING the below code is unsafe and only handles searches for direct flights
      // You can use the below code as a starting reference point or you can get rid
      // of it all and replace it with your own implementation.
      // TODO: YOUR CODE HERE
      StringBuffer sb = new StringBuffer();
      try {
        String unsafeSearchSQL = "SELECT TOP (" + numberOfItineraries
                + ") fid,day_of_month,carrier_id,flight_num,origin_city,dest_city,actual_time,capacity,price "
                + "FROM Flights " + "WHERE origin_city = \'" + originCity + "\' AND dest_city = \'"
                + destinationCity + "\' AND day_of_month =  " + dayOfMonth + "AND actual_time!=0"
                + "ORDER BY actual_time ASC";
        Statement searchStatement = conn.createStatement();
        ResultSet oneHopResults = searchStatement.executeQuery(unsafeSearchSQL);
        while (oneHopResults.next()) {
          int result_id = oneHopResults.getInt("fid");
          int result_dayOfMonth = oneHopResults.getInt("day_of_month");
          String result_carrierId = oneHopResults.getString("carrier_id");
          String result_flightNum = oneHopResults.getString("flight_num");
          String result_originCity = oneHopResults.getString("origin_city");
          String result_destCity = oneHopResults.getString("dest_city");
          int result_time = oneHopResults.getInt("actual_time");
          int result_capacity = oneHopResults.getInt("capacity");
          int result_price = oneHopResults.getInt("price");
          Flight onehopresult1=new Flight(result_id,result_dayOfMonth,result_carrierId,result_flightNum,result_originCity,result_destCity,result_time,result_capacity,result_price);
          IterTable.add(new Flight[]{onehopresult1});

        }

        oneHopResults.close();
      } catch (SQLException e) {
        e.printStackTrace();
      }

      if (directFlight == false && time<numberOfItineraries ) {
        try {
          String searchq = "SELECT TOP (" + (numberOfItineraries-time) + ") F1.fid as fid1, F1.day_of_month as day_of_month1,\n" +
                  "F1.carrier_id as carrier_id1,\n" +
                  "F1.flight_num as flight_num1, F1.origin_city as origin_city1, \n" +
                  "F1.dest_city as dest_city1, F1.actual_time as actual_time1,\n" +
                  "F1.capacity as capacity1, F1.price as price1,\n" +
                  "F2.fid as fid2, F2.day_of_month as day_of_month2,\n" +
                  "F1.carrier_id as carrier_id2,\n" +
                  "F2.flight_num as flight_num2, F2.origin_city as origin_city2,\n" +
                  "F2.dest_city as dest_city2, F2.actual_time as actual_time2,\n" +
                  "F2.capacity as capacity2, F2.price as price2,\n" +
                  "F1.actual_time + F2.actual_time as total_time\n" +
                  "\n" +
                  "FROM Flights F1, Flights F2, Carriers C1, Carriers C2\n" +
                  "WHERE F1.carrier_id = C1.cid AND F1.actual_time !=0 \n" +
                  "AND F2.carrier_id = C2.cid AND F2.actual_time !=0 \n" +
                  "AND F1.day_of_month = " + dayOfMonth + "\n" +
                  "AND F2.day_of_month = " +dayOfMonth + "\n" +
                  "AND F1.origin_city = '" + originCity + "'\n" +
                  "AND F2.dest_city = '" + destinationCity + "'\n" +
                  "AND F1.dest_city = F2.origin_city\n" +
                  "ORDER BY F1.actual_time + F2.actual_time ASC;";
          Statement st = conn.createStatement();
          ResultSet twoHopResults = st.executeQuery(searchq);
          int time2 = 0;
          while (twoHopResults.next() && time2<numberOfItineraries-IterTable.size()) {
            int result_id1 = twoHopResults.getInt("fid1");
            int dayOfMonth1 = twoHopResults.getInt("day_of_month1");
            String carrier_id1 = twoHopResults.getString("carrier_id1");
            String flight_num1 = twoHopResults.getString("flight_num1");
            int capacity1 = twoHopResults.getInt("capacity1");
            int price1 = twoHopResults.getInt("price1");
            String origin_city1 = twoHopResults.getString("origin_city1");
            String dest_city1 = twoHopResults.getString("dest_city1");
            int actual_time1 = (int) twoHopResults.getFloat("actual_time1");
            int result_id2 = twoHopResults.getInt("fid2");
            int dayOfMonth2 = twoHopResults.getInt("day_of_month2");
            String flight_num2 = twoHopResults.getString("flight_num2");
            int capacity2 = twoHopResults.getInt("capacity2");
            int price2 = twoHopResults.getInt("price2");
            String carrier_id2 = twoHopResults.getString("carrier_id2");
            String origin_city2 = twoHopResults.getString("origin_city2");
            String dest_city2 = twoHopResults.getString("dest_city2");
            int actual_time2 = (int) twoHopResults.getFloat("actual_time2");

            Flight twohopresult1=new Flight(result_id1,dayOfMonth1,carrier_id1,flight_num1,origin_city1,dest_city1,actual_time1,capacity1,price1);
            Flight twohopresult2=new Flight(result_id2,dayOfMonth2,carrier_id2,flight_num2,origin_city2,dest_city2,actual_time2,capacity2,price2);
            IterTable.add(new Flight[]{twohopresult1,twohopresult2});
            time2 += 1;
          }
          IterTable.sort(new flightComparator());
        } catch (SQLException e) {
          e.printStackTrace();
        }
      }
      for (int i=0;i<IterTable.size();i++){
        Flight[]tmp=IterTable.get(i);
        String dir="Itinerary " + i + ": " + tmp.length + " flight(s), " ;
        int t=tmp[0].time;
        if (tmp.length==2){
            t=tmp[0].time+tmp[1].time;
        }
        dir+=t+ " minutes\n";
        for (Flight f: tmp){
          dir+=f.toString()+"\n";
        }
        sb.append(dir);
      }
      return sb.toString();
    }
    finally {
      checkDanglingTransaction();
    }
  }
  public void getReservation(String username){
    try{
      String reservation="Select * From reservation as R WHERE username = "+"'"+username+"'";
      Statement reservations=conn.createStatement();
      reservations.execute(reservation);
      ResultSet result=reservations.getResultSet();
      Reservations.clear();
      Payment.clear();
      while (result.next()){
        int rid=Integer.parseInt( result.getString(1));
        int result_id = result.getInt("fid");
        int result_id2=result.getInt("fid2");
        //flight1
        String FLIGHT1="Select * From flights as f WHERE fid = "+result_id;
        Statement flight1=conn.createStatement();
        flight1.execute(FLIGHT1);
        //flight2
        String FLIGHT2="Select * From flights as f WHERE fid = "+result_id2;
        Statement flight2=conn.createStatement();
        flight2.execute(FLIGHT2);
        // flight1 and flight2 result
        ResultSet rflight1=flight1.getResultSet();
        ResultSet rflight2=flight2.getResultSet();
        rflight1.next();
        rflight2.next();
        int result_dayOfMonth = rflight1.getInt("day_of_month");
        String result_carrierId = rflight1.getString("carrier_id");
        String result_flightNum = rflight1.getString("flight_num");
        String result_originCity = rflight1.getString("origin_city");
        String result_destCity = rflight1.getString("dest_city");
        int result_time = rflight1.getInt("actual_time");
        int result_capacity = rflight1.getInt("capacity");
        int result_price = rflight1.getInt("price");
        Flight f=new Flight(result_id,result_dayOfMonth,result_carrierId,result_flightNum,result_originCity,result_destCity,result_time,result_capacity,result_price);
        Flight f2=null;

        if (result_id!=result_id2){
          int result_dayOfMonth2 = rflight2.getInt("day_of_month");
          String result_carrierId2 = rflight2.getString("carrier_id");
          String result_flightNum2 = rflight2.getString("flight_num");
          String result_originCity2 = rflight2.getString("origin_city");
          String result_destCity2 = rflight2.getString("dest_city");
          int result_time2 = rflight2.getInt("actual_time");
          int result_capacity2 = rflight2.getInt("capacity");
          int result_price2 = rflight2.getInt("price");
          f2=new Flight(result_id2,result_dayOfMonth2,result_carrierId2,result_flightNum2,result_originCity2,result_destCity2,result_time2,result_capacity2,result_price2);
        }

        boolean pay=result.getBoolean("pay");
        Flight[] flights;
        if (f2==null){
           flights=new Flight[]{f};
        }
        else {
          flights=new Flight[]{f,f2};
        }
        Reservations.put(rid,flights);
        Payment.put(rid,pay);
      }

      result.close();
    }
    catch (SQLException o){
    }
  }
  public boolean isPlaneFULL(Flight[] flights){
    try {
      for (Flight flight:flights){
        int capacity= flight.capacity;
        String CHECK_CAPACITY="Select count(*) as count From reservation as R Where fid="+flight.fid+"Group by fid";
        Statement get_capacity=conn.createStatement();
        get_capacity.execute(CHECK_CAPACITY);
        ResultSet capacity_result=get_capacity.getResultSet();
        if(!capacity_result.next()) {
          return false;
        }
        int ct=capacity_result.getInt("count");
        capacity_result.close();
        return capacity-ct==0;
      }
      return false;
    }
    catch (SQLException o){
      return false;
    }
  }
  public boolean isDateValid(Flight[] flights){
    try {
      for(Flight flight: flights){
        String DATE="Select day_of_month From reservation as R Where R.username = "+"'"+login_user+"'";
        Statement date=conn.createStatement();
        date.execute(DATE);
        ResultSet result=date.getResultSet();
        while (result.next()){
          int dayofmonth1 = result.getInt("day_of_month");
          if (flight.dayOfMonth==dayofmonth1){
            result.close();
            return false;
          }
        }
        result.close();
      }
      return true;
    }
    catch (SQLException o){
      return false;
    }
  }
  /**
   * Implements the book itinerary function.
   *
   * @param itineraryId ID of the itinerary to book. This must be one that is returned by search in
   *                    the current session.
   *
   * @return If the user is not logged in, then return "Cannot book reservations, not logged in\n".
   *         If the user is trying to book an itinerary with an invalid ID or without having done a
   *         search, then return "No such itinerary {@code itineraryId}\n". If the user already has
   *         a reservation on the same day as the one that they are trying to book now, then return
   *         "You cannot book two flights in the same day\n". For all other errors, return "Booking
   *         failed\n".
   *
   *         And if booking succeeded, return "Booked flight(s), reservation ID: [reservationId]\n"
   *         where reservationId is a unique number in the reservation system that starts from 1 and
   *         increments by 1 each time a successful reservation is made by any user in the system.
   */

  public String transaction_book(int itineraryId) {
    if (login_user == null) return "Cannot book reservations, not logged in\n";
    if (IterTable.size()-1<itineraryId||itineraryId<0){
      return "No such itinerary "+itineraryId+"\n";
    }
    try {
      // TODO: YOUR CODE HERE
      //setting get the flight and Reservation
      beginTransaction();
      getReservation(login_user);
      Flight[] flights=IterTable.get(itineraryId);
      int[] rid=new int[2];
      int ct=0;
      Flight f1=flights[0];
      Flight f2=flights[0];
      if (flights.length==2) f2=flights[1];
      // 1. capacity,
      if (isPlaneFULL(flights)==true)  {
        rollbackTransaction();
        return "Booking failed\n";
      }
      // 2. user cannot book in same date
      if (!isDateValid(flights)){
        rollbackTransaction();
        return "You cannot book two flights in the same day\n";
      }
      String BOOK="INSERT INTO RESERVATION VALUES("
                +"'"+login_user+"'"
                +","+f1.fid
                +","+f2.fid
                +","+f1.dayOfMonth
                +","+0+
                ")";
      Statement book=conn.createStatement();
      book.executeUpdate(BOOK,Statement.RETURN_GENERATED_KEYS);
      ResultSet rs=book.getGeneratedKeys();
      rs.next();
      rid[ct]=rs.getInt(1);
      commitTransaction();
      return "Booked flight(s), reservation ID: "+rid[0]+"\n";
    }catch (SQLException o){
      return "Booking failed\n";
    }
    finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implements the pay function.
   *
   * @param reservationId the reservation to pay for.
   *
   * @return If no user has logged in, then return "Cannot pay, not logged in\n" If the reservation
   *         is not found / not under the logged in user's name, then return "Cannot find unpaid
   *         reservation [reservationId] under user: [username]\n" If the user does not have enough
   *         money in their account, then return "User has only [balance] in account but itinerary
   *         costs [cost]\n" For all other errors, return "Failed to pay for reservation
   *         [reservationId]\n"
   *
   *         If successful, return "Paid reservation: [reservationId] remaining balance:
   *         [balance]\n" where [balance] is the remaining balance in the user's account.
   */
  public String transaction_pay(int reservationId) {
    if (login_user==null) return "Cannot pay, not logged in\n";
    getReservation(login_user);
    if (!Payment.containsKey(reservationId)){
      return "Cannot find unpaid reservation "+reservationId+" under user: " +login_user+ "\n";
    }
    try {
      // TODO: YOUR CODE HERE
      beginTransaction();
      String GETUSER="Select * From users Where username="+"'"+login_user+"'";
      Statement getuser=conn.createStatement();
      getuser.execute(GETUSER);
      ResultSet result=getuser.getResultSet();
      result.next();
      int balance=result.getInt("balance");
      getReservation(login_user);

      Flight[] flights=Reservations.get(reservationId);

      int price=0;

      for(Flight flight:flights){
        price +=flight.price;
      }
      if(balance<price){
        rollbackTransaction();
        return "User has only "+balance+" in account but itinerary costs "+price+"\n";
      }
      try (PreparedStatement checkAccountExists = conn.prepareStatement(
              "SELECT BALANCE FROM users WHERE username = ?"))
      {
        checkAccountExists.setString(1, login_user);
        try (ResultSet RS = checkAccountExists.executeQuery()) {
          if (RS.next()) {
            int ebalance = RS.getInt("balance");
            int newbalance = ebalance-price;
            try (PreparedStatement stmt = conn.prepareStatement(
                    "UPDATE users SET BALANCE = ? WHERE username = ?")){
              stmt.setInt(1, newbalance);
              stmt.setString(2, login_user);
              stmt.executeUpdate();
            }
          } else {
            rollbackTransaction();
            return "INVALID USER";
          }
        }
      }
      try (PreparedStatement payment = conn.prepareStatement(
              "SELECT pay FROM reservation WHERE rid = ?"))
      {
        payment.setInt(1, reservationId);
        try (ResultSet RS = payment.executeQuery()) {
          if (RS.next()) {
            if (RS.getBoolean("pay")) {
              rollbackTransaction();
              return "Cannot find unpaid reservation "+reservationId+ " under user: " +login_user+ "\n";
            }
            try (PreparedStatement stmt = conn.prepareStatement(
                    "UPDATE reservation SET pay = ? WHERE rid = ?")){
              stmt.setInt(1, 1);
              stmt.setInt(2, reservationId);
              stmt.executeUpdate();
            }

          } else {
            rollbackTransaction();
            return "INVALID PAY";
          }
        }
      }
      commitTransaction();
      Payment.put(reservationId,true);
      return "Paid reservation: "+reservationId+" remaining balance: "+(balance-price)+"\n";

    }
    catch (SQLException  o){
      return "Failed to pay for reservation " + reservationId + "\n";
    }
    finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implements the reservations function.
   *
   * @return If no user has logged in, then return "Cannot view reservations, not logged in\n" If
   *         the user has no reservations, then return "No reservations found\n" For all other
   *         errors, return "Failed to retrieve reservations\n"
   *
   *         Otherwise return the reservations in the following format:
   *
   *         Reservation [reservation ID] paid: [true or false]:\n [flight 1 under the
   *         reservation]\n [flight 2 under the reservation]\n Reservation [reservation ID] paid:
   *         [true or false]:\n [flight 1 under the reservation]\n [flight 2 under the
   *         reservation]\n ...
   *
   *         Each flight should be printed using the same format as in the {@code Flight} class.
   *
   * @see Flight#toString()
   */
  public String transaction_reservations() {

    int time = 0;
    if (login_user == null) return "Cannot view reservations, not logged in\n";
    getReservation(login_user);
    if (Reservations.size() == 0) return "No reservations found\n";
    try {
      StringBuffer sb3 = new StringBuffer();
      try {
        // TODO: YOUR CODE HERE
        Iterator<Map.Entry<Integer,Flight[]>> itr=Reservations.entrySet().iterator();
        Iterator<Map.Entry<Integer,Boolean>> itr2=Payment.entrySet().iterator();
        while (itr.hasNext()&&itr2.hasNext()){
          Map.Entry e1=itr.next();
          Map.Entry e2=itr2.next();
          Flight[] tmp=(Flight[])e1.getValue();
          sb3.append("Reservation "+e1.getKey()+" paid: "+e2.getValue().toString()+":"+"\n");
//          sb3.append(e2.getValue().toString()+"\n");
          if(tmp.length==1) sb3.append(tmp[0].toString()+"\n");
          else{
            sb3.append(tmp[0].toString() +"\n"+tmp[1].toString()+"\n");
          }

        }
        return sb3.toString();
      } catch (Exception e) {
        e.printStackTrace();
      }
      return "Failed to retrieve reservations\n";
    } finally {
      checkDanglingTransaction();
    }
  }
  /**
   * Implements the cancel operation.
   *
   * @param reservationId the reservation ID to cancel
   *
   * @return If no user has logged in, then return "Cannot cancel reservations, not logged in\n" For
   *         all other errors, return "Failed to cancel reservation [reservationId]\n"
   *
   *         If successful, return "Canceled reservation [reservationId]\n"
   *
   *         Even though a reservation has been canceled, its ID should not be reused by the system.
   */
  public String transaction_cancel(int reservationId) {
    if (login_user==null) return "Cannot cancel reservations, not logged in\n";
    getReservation(login_user);
    if (!Reservations.containsKey(reservationId)) return "Failed to cancel reservation "+reservationId+"\n";
    try {
      // TODO: YOUR CODE HERE
      beginTransaction();

      //getReservation(login_user);

      Flight[] flights=Reservations.get(reservationId);

      Boolean pay=Payment.get(reservationId);

      int price=0;
      for(Flight flight:flights){

          price +=flight.price;
      }
      if(pay){
        try (PreparedStatement checkAccountExists = conn.prepareStatement(
                "SELECT BALANCE FROM users WHERE username = ?"))
        {
          checkAccountExists.setString(1, login_user);
          try (ResultSet RS = checkAccountExists.executeQuery()) {
            if (RS.next()) {
              int ebalance = RS.getInt("balance");
              int newbalance = ebalance+price;
              try (PreparedStatement stmt = conn.prepareStatement(
                      "UPDATE users SET BALANCE = ? WHERE username = ?")){
                stmt.setInt(1, newbalance);
                stmt.setString(2, login_user);
                stmt.executeUpdate();
              }

            } else {
              rollbackTransaction();
              return "INVALID USER ";
            }
          }
        }
      }
      String REMOVE_RESERVATION_SQL = "DELETE FROM RESERVATION WHERE rid = " +reservationId;
      Statement st =conn.createStatement();
      st.execute(REMOVE_RESERVATION_SQL);

      getReservation(login_user);
      commitTransaction();
      return  "Canceled reservation "+reservationId+"\n";
    } catch (SQLException e) {
      return "Failed to cancel reservation " + reservationId + "\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  public void beginTransaction() throws SQLException {
    conn.setAutoCommit(false);  // do not commit until explicitly requested
    beginTxnStmt.executeUpdate();
  }

  public void commitTransaction() throws SQLException {
    commitTxnStmt.executeUpdate();
    conn.setAutoCommit(true);  // go back to one transaction per statement
  }

  public void rollbackTransaction() throws SQLException {
    abortTxnStmt.executeUpdate();
    conn.setAutoCommit(true);  // go back to one transaction per statement
  }

  /**
   * Example utility function that uses prepared statements
   */
  private int checkFlightCapacity(int fid) throws SQLException {
    checkFlightCapacityStatement.clearParameters();
    checkFlightCapacityStatement.setInt(1, fid);
    ResultSet results = checkFlightCapacityStatement.executeQuery();
    results.next();
    int capacity = results.getInt("capacity");
    results.close();
    return capacity;
  }

  /**
   * Throw IllegalStateException if transaction not completely complete, rollback.
   *
   */
  private void checkDanglingTransaction() {
    try {
      try (ResultSet rs = tranCountStatement.executeQuery()) {
        rs.next();
        int count = rs.getInt("tran_count");
        if (count > 0) {
          throw new IllegalStateException(
                  "Transaction not fully commit/rollback. Number of transaction in process: " + count);
        }
      } finally {
        conn.setAutoCommit(true);
      }
    } catch (SQLException e) {
      throw new IllegalStateException("Database error", e);
    }
  }

  private static boolean isDeadLock(SQLException ex) {
    return ex.getErrorCode() == 1205;
  }
  class flightComparator implements Comparator {
    public int compare(Object o1, Object o2) {
      Flight[] s1 = (Flight[]) o1;
      Flight[] s2 = (Flight[]) o2;
      int time1 = 0;
      int time2 = 0;
      int fid = 0;
      int fid2 = 0;
      for (Flight f : s1) {
        fid=f.fid;
        time1 += f.time;
      }
      for (Flight f : s2) {
        fid2=f.fid;
        time2 += f.time;
      }

      if (time1 == time2) {
        if (fid > fid2)
          return 1;
        else {
          return -1;
        }
      } else if (time1 > time2)
        return 1;
      else
      return -1;
    }
  }
  /**
   * A class to store flight information.
   */
  class Flight {
    public int fid;
    public int dayOfMonth;
    public String carrierId;
    public String flightNum;
    public String originCity;
    public String destCity;
    public int time;
    public int capacity;
    public int price;
    public Flight(
            int id, int dayOfMonth, String carrierId,
            String flightNum, String originCity, String destCity, int timeMinutes,int capacity,int price) {
      this.fid = id;
      this.dayOfMonth = dayOfMonth;
      this.carrierId = carrierId.trim();
      this.flightNum = flightNum.trim();
      this.originCity = originCity.trim();
      this.destCity = destCity.trim();
      this.time = timeMinutes;
      this.capacity=capacity;
      this.price=price;
    }
    @Override
    public String toString() {
      return "ID: " + fid + " Day: " + dayOfMonth + " Carrier: " + carrierId + " Number: "
              + flightNum + " Origin: " + originCity + " Dest: " + destCity + " Duration: " + time
              + " Capacity: " + capacity + " Price: " + price;
    }
  }
}
