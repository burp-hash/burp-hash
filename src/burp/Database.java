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
	private PreparedStatement pstmt = null; //TODO: prepared statements for inserting data
	private PrintWriter stdErr;
	private PrintWriter stdOut;

	private final String connPrefix = "jdbc:sqlite:";
	private final String sql_tableCheck = "SELECT name FROM sqlite_master WHERE type='table' AND name='params';";
	private final String sql_dropTables = "DROP TABLE IF EXISTS params; DROP TABLE IF EXISTS hashes; DROP TABLE IF EXISTS algorithms;";
	private final String sql_createAlgoTable = "CREATE TABLE algorithms (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, Name TEXT NOT NULL)";
	private final String sql_createParamTable = "CREATE TABLE params (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, url TEXT)";
	private final String sql_createHashTable = "CREATE TABLE hashes (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, algorithmID INTEGER NOT NULL, paramID INTEGER NOT NULL, value TEXT NOT NULL)";
	private final String sql_insertAlgo = "INSERT OR REPLACE INTO algorithms(name, ID) VALUES (?, ?)";
	private final String sql_insertParams = "INSERT OR REPLACE INTO params(name, value, url) VALUES (?, ?, ?)";
	private final String sql_insertHashes = "INSERT OR REPLACE INTO hashes(algorithmID, paramID, value) VALUES (?, ?, ?)";
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
		burpExtender.loadHashes();
		burpExtender.loadHashedParameters();
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
			stmt.executeUpdate(sql_dropTables);
			stmt.executeUpdate(sql_createAlgoTable);
			stmt.executeUpdate(sql_createParamTable);
			stmt.executeUpdate(sql_createHashTable);
			stdOut.println("DB init: hash algorithm count: " + config.hashAlgorithms.size());
			Collections.reverse(config.hashAlgorithms); //so the db has ascending order
			for (HashAlgorithm algo : config.hashAlgorithms)
			{
				pstmt = conn.prepareStatement(sql_insertAlgo);
				pstmt.setString(1, algo.name.text);
				pstmt.setString(2, Integer.toString(algo.id));
				pstmt.executeUpdate();
				stdOut.println("Adding Hash Algorithm to DB: " + algo.name.text + ":" + algo.id);
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

	/**
	 * TODO: add methods for storing/retrieving data
	 * Parameter param = new Parameter();
			param.name = item.getName();
			param.value = item.getValue();
			for (HashAlgorithmName algorithm : hashTracker)
			{
				try
				{
					ParameterHash hash = new ParameterHash();
	 */
	boolean upsert(Parameter toUpsert, ParameterHash hashedParam) {
		//Want to update if param_name+hashalgo exists, insert if not
		try {
			if (conn == null) {
				conn = getConnection();
				}
			//insert a hash in db for all observedHashTypes
			pstmt = conn.prepareStatement(sql_insertParams);
			pstmt.setString(1, toUpsert.name);
			pstmt.setString(2, toUpsert.value);
			pstmt.setString(3, hashedParam.algorithm.toString());
			pstmt.setString(4, hashedParam.hashedValue);
			pstmt.executeUpdate();
			stdOut.println("Adding Found Parameter to DB: " + toUpsert.name + ":" + toUpsert.value + " " + hashedParam.algorithm.toString());
			return true;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return false;
		}
	}
	
	String exists(ParameterHash hashedParam) {
		// return parameter value if the hash already exists
		try {
			if (conn == null) {
				conn = getConnection();
				}
			//insert a hash in db for all observedHashTypes
			pstmt = conn.prepareStatement(sql_hashCheck);
			pstmt.setString(1, hashedParam.hashedValue);
			stdOut.println("Searching DB for: " + hashedParam.hashedValue);
			ResultSet rs = pstmt.executeQuery();
			String results = rs.getString("hashAlgo");
			//if result, return SHA1:test@email.com
			if(results != null && !results.isEmpty()) {
				stdOut.println("FOUND MATCH FOR: " + hashedParam.hashedValue + " is " + rs.getString("value"));
				return results + ":" + rs.getString("value");
			}
			else
				return null;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return null;
		}
	}

	/**
	 * TODO: verify presence of all tables? (params, hashes, etc.)
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