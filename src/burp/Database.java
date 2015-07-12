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
		this.callbacks = b.getCallbacks();
		this.config = b.getConfig();
		this.stdErr = b.getStdErr();
		try {
			// the following line loads the JDBC Driver
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException e) {
			this.stdErr.println(e.getMessage());
		}
	}

	public boolean close() {
		try {
			if (this.conn != null)
				this.conn.close();
			return true;
		} catch (SQLException e) {
			this.stdErr.println(e.getMessage());
			return false;
		}
	}

	/**
	 * TODO: this might need some tweaking
	 */
	protected void finalize() throws Throwable {
		try {
			if (this.conn != null)
				conn.close();
		}
		finally {
			super.finalize();
		}
	}

	private Connection getConnection() {
		Connection connection;
		try {
			connection = DriverManager.getConnection(this.connPrefix
					+ this.config.databaseFilename);
		} catch (SQLException e) {
			this.stdErr.println(e.getMessage());
			return null;
		}
		return connection;
	}

	/**
	 * TODO: drop/create all necessary tables (params, hashes, etc.)
	 */
	public boolean init() {
		Statement stmt = null;
		try {
			if (this.conn == null) {
				this.conn = this.getConnection();
			}
			stmt = conn.createStatement();
			stmt.setQueryTimeout(30);
			stmt.executeUpdate(this.sql_dropTable);
			stmt.executeUpdate(this.sql_createTable);
			return true;
		} catch (SQLException e) {
			this.stdErr.println(e.getMessage());
			return false;
		}
	}

	/**
	 * TODO: verify presence of all tables? (params, hashes, etc.)
	 *
	 * Another option would be to simply do away with this method altogether
	 * and instead perform "CREATE TABLE IF NOT EXISTS" operations for all
	 * tables every time the extension loads.
	 */
	public boolean verify() {
		Statement stmt = null;
		ResultSet rs = null;

		try {
			if (this.conn == null) {
				this.conn = this.getConnection();
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
			this.stdErr.println(e.getMessage());
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
			if (this.conn == null) {
				this.conn = this.getConnection();
				}
			//insert a hash in db for all observedHashTypes
			for (HashAlgorithmName n: obervedHashTypes){
				this.pstmt = conn.prepareStatement(this.insert_statement);
				this.pstmt.setString(1, toUpsert.name);
				this.pstmt.setString(2, toUpsert.value);
				this.pstmt.setString(3, n.toString());
				this.pstmt.setString(4, E.returnHash(n, toUpsert.value));
				this.pstmt.executeUpdate();
			}
			return true;
		} catch (SQLException e) {
			this.stdErr.println(e.getMessage());
			return false;
		}
	}
}