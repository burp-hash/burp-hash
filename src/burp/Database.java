package burp;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.Set;

import org.sqlite.SQLiteConfig;

/**
 * Handles SQLite database access
 */
class Database {
	private BurpExtender burpExtender;
	private Config config;
	private Connection conn = null;
	private IBurpExtenderCallbacks callbacks;
	private PreparedStatement pstmt = null;
	private PrintWriter stdErr;
	private PrintWriter stdOut;

	private final String connPrefix = "jdbc:sqlite:";
	private final String sql_tableCheck = "SELECT name FROM sqlite_master WHERE type='table' AND name='params';";
	private final String sql_insertAlgo = "INSERT OR REPLACE INTO algorithms(name, ID) VALUES (?, ?)";
	private final String sql_insertParam = "INSERT OR REPLACE INTO params(name, value, url) VALUES (?, ?, ?)";
	private final String sql_hashCheck = "SELECT * FROM params WHERE hash=?;";


	Database(BurpExtender b) {
		burpExtender = b;
		callbacks = b.getCallbacks();
		config = b.getConfig();
		stdErr = b.getStdErr();
		stdOut = b.getStdOut();
		try {
			// the following line loads the JDBC Driver
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException e) {
			stdErr.println(e.getMessage());
		}
	}

	/**
	 * open a different database file after a config change
	 */
	void changeFile() {
		close();
		conn = getConnection();
	}

	/**
	 * close the database connection
	 */
	boolean close() {
		try {
			if (conn != null)
				conn.close();
			return true;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return false;
		}
	}

	/**
	 * TODO: this might need some tweaking
	 */
	protected void finalize() throws Throwable {
		try {
			if (conn != null)
				conn.close();
		}
		finally {
			super.finalize();
		}
	}

	/**
	 * open and return database connections
	 */
	private Connection getConnection() {
		Connection connection;
		SQLiteConfig sc = new SQLiteConfig();
		sc.setEncoding(SQLiteConfig.Encoding.UTF_8);
		try {
			connection = DriverManager.getConnection(connPrefix
					+ config.databaseFilename, sc.toProperties());
			stdOut.println("Opened database file: " + config.databaseFilename);
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return null;
		}
		return connection;
	}

	/**
	 * initialize the database
	 * TODO: drop/create all necessary tables (params, hashes, etc.)
	 */
	boolean init() {
		Statement stmt = null;
		try {
			if (conn == null) {
				conn = getConnection();
			}
			stmt = conn.createStatement();
			stmt.setQueryTimeout(30);
			stdOut.println(" + Rebuilding all DB tables.");
			String sql_dropTables = "DROP TABLE IF EXISTS params; DROP TABLE IF EXISTS hashes; DROP TABLE IF EXISTS algorithms;";
			stmt.executeUpdate(sql_dropTables);
			String sql_createAlgoTable = "CREATE TABLE algorithms (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, Name TEXT NOT NULL)";
			stmt.executeUpdate(sql_createAlgoTable);
			String sql_createParamTable = "CREATE TABLE params (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, url TEXT)";
			stmt.executeUpdate(sql_createParamTable);
			String sql_createHashTable = "CREATE TABLE hashes (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, algorithmID INTEGER NOT NULL, paramID INTEGER NULL, value TEXT NOT NULL)";
			stmt.executeUpdate(sql_createHashTable);
			stdOut.println(" + Adding " + config.hashAlgorithms.size() + " hash algorithms to DB:");
			Collections.reverse(config.hashAlgorithms); //so the db has ascending order
			for (HashAlgorithm algo : config.hashAlgorithms)
			{
				pstmt = conn.prepareStatement(sql_insertAlgo);
				pstmt.setString(1, algo.name.text);
				pstmt.setString(2, Integer.toString(algo.id));
				pstmt.executeUpdate();
				stdOut.println(" + Adding Hash Algorithm to DB: " + algo.name.text + ":" + algo.id);
			}
			Collections.reverse(config.hashAlgorithms); //back to descending order for hash searching
			return true;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return false;
		}
		catch (Exception ex)
		{
			stdErr.println(ex);
			return false;
		}
	}
	
	boolean saveParam(Parameter param, String url) {
		if (getParamId(param) <= 0)
		{
			return false;
		}
		try {
			if (conn == null) {
				conn = getConnection();
			}
			pstmt = conn.prepareStatement(sql_insertParam);
			pstmt.setString(1, param.name);
			pstmt.setString(2, param.value);
			pstmt.setString(3, url); //optional
			pstmt.executeUpdate();
			stdOut.println("DB: Saving Discovered Parameter: " + param.name + ":" + param.value);
			return true;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return false;
		}
	}
	
	int getParamId(Parameter param)
	{
		try {
			if (conn == null) {
				conn = getConnection();
			}
			String sql_paramExists = "SELECT * from params where name = ? and value = ?";
			pstmt = conn.prepareStatement(sql_paramExists);
			pstmt.setString(1, param.name);
			pstmt.setString(2, param.value);
			ResultSet rs = pstmt.executeQuery();
			if (!rs.next()) {
				return 0;
			}
			return rs.getInt("id");
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return -1;
		}
	}
	
	boolean saveParamHash(Parameter param, ParameterHash hash) {
		int paramId = getParamId(param);
		if (paramId <= 0)
		{
			stdOut.println("DB: Cannot save hash " + hash.hashedValue + " until the following parameter is saved " + param.name + ":" + param.value);
			saveParam(param, "");
			paramId = getParamId(param);
		}
		try {
			if (conn == null) {
				conn = getConnection();
			}
			int algorithmId = config.getHashId(hash.algorithm);
			if (algorithmId <= 0)
			{
				stdErr.println("DB: Could not locate Algorithm ID for " + hash.algorithm);
				return false;
			}
			String sql_insertHash = "INSERT OR REPLACE INTO hashes(algorithmID, paramID, value) VALUES (?, ?, ?)";
			pstmt = conn.prepareStatement(sql_insertHash);
			pstmt.setString(1, Integer.toString(algorithmId));
			pstmt.setString(2, Integer.toString(paramId));
			pstmt.setString(3, hash.hashedValue); 
			pstmt.executeUpdate();
			stdOut.println("DB: Saving Parameter Hash to DB: " + param.name + ":" + param.value + ":" + hash.algorithm + ":" + hash.hashedValue);
			return true;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return false;
		}
	}
	
	boolean saveHash(HashRecord hash) {
		if (getHashIdByValue(hash.getNormalizedRecord()) > 0)
		{
			stdOut.println("DB: Not saving hash (" + hash.getNormalizedRecord() + ") since it's already in the db.");
			return false;
		}
		try {
			if (conn == null) {
				conn = getConnection();
			}
			int algorithmId = config.getHashId(hash.algorithm);
			if (algorithmId <= 0)
			{
				stdErr.println("DB: Could not locate Algorithm ID for " + hash.algorithm);
				return false;
			}
			String sql_insertHash = "INSERT OR REPLACE INTO hashes(algorithmID, value) VALUES (?, ?)";
			pstmt = conn.prepareStatement(sql_insertHash);
			pstmt.setString(1, Integer.toString(algorithmId));
			pstmt.setString(2, hash.getNormalizedRecord());
			pstmt.executeUpdate();
			stdOut.println("DB: Saving Hash of Unknown Source Value to DB: " + hash.algorithm.text + ":" + hash.getNormalizedRecord());
			return true;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return false;
		}
	}
	
	int getHashIdByValue(String hashedValue)
	{
		try {
			if (conn == null) {
				conn = getConnection();
			}
			//TODO: Could just search on value only, rather than algorithmID:
			String sql_hashExists = "SELECT * from hashes where value = ?";
			pstmt = conn.prepareStatement(sql_hashExists);
			pstmt.setString(1, hashedValue);
			ResultSet rs = pstmt.executeQuery();
			if (!rs.next()) {
				stdOut.println("DB: Did not locate " + hashedValue + " in the DB.");
				return 0;
			}
			stdOut.println("DB: Found hash (" + hashedValue +") in the db at ID=" + rs.getInt("id"));
			return rs.getInt("id");
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return -1;
		}
	}
	
	// This is for searching for previously observed params with missing hashes for new algorithm types
	int getHashIdByAlgorithmAndParam(Parameter param, HashAlgorithmName algorithmName)
	{
		try {
			if (conn == null) {
				conn = getConnection();
			}
			int algorithmId = config.getHashId(algorithmName);
			if (algorithmId <= 0)
			{
				stdErr.println("DB: Could not locate Algorithm ID for " + algorithmName);
				return -1;
			}
			int paramId = getParamId(param);
			String sql_hashExists = "SELECT * from hashes where algorithmID = ? and paramID = ?";
			pstmt = conn.prepareStatement(sql_hashExists);
			pstmt.setString(1, Integer.toString(algorithmId));
			pstmt.setString(2, Integer.toString(paramId));
			ResultSet rs = pstmt.executeQuery();
			if (!rs.next()) {
				return 0;
			}
			return rs.getInt("id");
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return -1;
		}
	}

	/**
	 * TODO: verify presence of all tables? (params, hashes, etc.) < Yes please, but !MVP [TM]
	 */
	boolean verify() {
		Statement stmt = null;
		ResultSet rs = null;

		try {
			if (conn == null) {
				conn = getConnection();
			}
			stmt = conn.createStatement();
			stmt.setQueryTimeout(30);
			rs = stmt.executeQuery(sql_tableCheck);
			boolean x = false;
			while (rs.next()) {
				x = true;
			}
			return x;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return false;
		}
	}
}