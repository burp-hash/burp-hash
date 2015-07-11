package burp;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Handles SQLite database access
 */
public class Database {
	private Connection conn = null;
	private PreparedStatement pstmt = null; //TODO: prepared statements for inserting data
	private PrintWriter stdErr;

	private String sql_tableCheck = "SELECT name FROM sqlite_master WHERE type='table' AND name='params';";
	private String sql_dropTable = "DROP TABLE IF EXISTS params;";
	//TODO: design table schemas
	// REF: https://www.sqlite.org/datatype3.html
	private String sql_createTable = "CREATE TABLE params (name TEXT PRIMARY KEY NOT NULL, hash TEXT NOT NULL);";

	public Database(IBurpExtenderCallbacks c) {
		stdErr = new PrintWriter(c.getStderr(), true);
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

	/**
	 * TODO: drop/create all necessary tables (params, hashes, etc.)
	 */
	public boolean init() {
		Statement stmt = null;
		try {
			if (this.conn == null) {
				this.conn = DriverManager
						.getConnection("jdbc:sqlite:burp-hash.db");
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
				this.conn = DriverManager
						.getConnection("jdbc:sqlite:burp-hash.db");
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
	
	public boolean upsert(Parameter toUpsert) {
		try {
			//don't know that we need this, but couldn't hurt
			if (this.conn == null) {
				this.conn = DriverManager
						.getConnection("jdbc:sqlite:burp-hash.db");
			}
			//Want to update if exists, update if not
			//INSERT OR REPLACE INTO table(name, hash) VALUES (toUpsert.name, toUpsert.hash);
			return true;
		} catch (SQLException e) {
			this.stdErr.println(e.getMessage());
			return false;
		}
	}
}