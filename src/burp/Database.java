package burp;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.EnumSet;
import java.util.Set;

/**
 * Handles SQLite database access
 */
public class Database {
	private Config config;
	private Connection conn = null;
	private IBurpExtenderCallbacks callbacks;
	private PreparedStatement pstmt = null; //TODO: prepared statements for inserting data
	private PrintWriter stdErr;
	private PrintWriter stdOut;

	private final String connPrefix = "jdbc:sqlite:";
	private final String sql_tableCheck = "SELECT name FROM sqlite_master WHERE type='table' AND name='params';";
	private final String sql_dropTable = "DROP TABLE IF EXISTS params;";
	private final String insert_statement = "INSERT OR REPLACE INTO params(name, value, hashAlgo, hash) VALUES (?, ?, ?, ?)";
	/*TODO: design table schemas. So we have parameter name, value, hashedvalue for each observed hash type
		    I guess the big question is, do we want to base it on 
		    	unique parameter value [would grow huge if the site uses CSRF tokens for example]
		    	or unique parameter name[csrf_token would have one record that would be updated each time]
		    	I'm opting for the former to keep the db smaller*/
	// REF: https://www.sqlite.org/datatype3.html
	//Primary key is parametername+hashalgo, EG: email_Param+SHA256 and email_Param+MD5 would be two diff records
	//Sorry for the flat DB, upserting items and deleting foreign keys in multiple tables sounds like trouble to me
	private final String sql_createTable = "CREATE TABLE params (name TEXT NOT NULL, value TEXT NOT NULL, hashAlgo TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(name, hashAlgo));";
	public Database(BurpExtender b) {
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
	public void changeFile() {
		close();
		conn = getConnection();
	}

	/**
	 * close the database connection
	 */
	public boolean close() {
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
		try {
			connection = DriverManager.getConnection(connPrefix
					+ config.databaseFilename);
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
	public boolean init() {
		Statement stmt = null;
		try {
			if (conn == null) {
				conn = getConnection();
			}
			stmt = conn.createStatement();
			stmt.setQueryTimeout(30);
			stmt.executeUpdate(sql_dropTable);
			stmt.executeUpdate(sql_createTable);
			return true;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return false;
		}
	}

	/**
	 * TODO: add methods for storing/retrieving data
	 */
	public boolean upsert(Parameter toUpsert, Set<HashAlgorithmName> obervedHashTypes) {
		//Want to update if param_name+hashalgo exists, insert if not
		HashingEngine E = new HashingEngine();
		try {
			if (conn == null) {
				conn = getConnection();
				}
			//insert a hash in db for all observedHashTypes
			for (HashAlgorithmName n: obervedHashTypes){
				pstmt = conn.prepareStatement(insert_statement);
				pstmt.setString(1, toUpsert.name);
				pstmt.setString(2, toUpsert.value);
				pstmt.setString(3, n.toString());
				pstmt.setString(4, E.returnHash(n, toUpsert.value));
				pstmt.executeUpdate();
			}
			return true;
		} catch (SQLException e) {
			stdErr.println(e.getMessage());
			return false;
		}
	}

	/**
	 * TODO: verify presence of all tables? (params, hashes, etc.)
	 */
	public boolean verify() {
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