package burp;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.sqlite.SQLiteConfig;

import com.sun.webkit.ThemeClient;

/**
 * Handles SQLite database access
 */
class Database {
	private Config config;
	private Connection conn = null;
	private PreparedStatement pstmt = null;
	private PrintWriter stdErr;
	private PrintWriter stdOut;
	private final String moduleName = "DB";
	private final String connPrefix = "jdbc:sqlite:";

	Database(BurpExtender b) 
	{
		config = b.getConfig();
		stdErr = b.getStdErr();
		stdOut = b.getStdOut();
		try 
		{
			Class.forName("org.sqlite.JDBC"); // load the JDBC Driver
		} 
		catch (ClassNotFoundException e) 
		{
			stdErr.println(e.getMessage());
		}
	}

	/**
	 * open a different database file after a config change
	 */
	void changeFile() 
	{
		close();
		conn = getConnection();
	}

	/**
	 * close the database connection
	 */
	boolean close() 
	{
		try 
		{
			if (conn != null)
			{
				conn.close();
			}
			return true;
		} 
		catch (SQLException e) 
		{
			stdErr.println(e.getMessage());
			return false;
		}
	}

	/**
	 * TODO: this might need some tweaking
	 */
	protected void finalize() throws Throwable 
	{
		try 
		{
			if (conn != null)
			{
				conn.close();
			}
		}
		finally 
		{
			super.finalize();
		}
	}

	/**
	 * open and return database connections
	 */
	private Connection getConnection() 
	{
		Connection connection;
		SQLiteConfig sc = new SQLiteConfig();
		sc.setEncoding(SQLiteConfig.Encoding.UTF_8);
		try 
		{
			connection = DriverManager.getConnection(connPrefix
					+ config.databaseFilename, sc.toProperties());
			stdOut.println(moduleName + ": Opened database file: " + config.databaseFilename);
		} 
		catch (SQLException e) 
		{
			stdErr.println(e.getMessage());
			return null;
		}
		return connection;
	}

	/**
	 * initialize the database
	 */
	boolean init() 
	{
		Statement stmt = null;
		try 
		{
			if (conn == null) 
			{
				conn = getConnection();
			}
			stmt = conn.createStatement();
			stmt.setQueryTimeout(30);
			stdOut.println(" + Rebuilding all DB tables.");
			String sql_dropTables = "DROP TABLE IF EXISTS params; DROP TABLE IF EXISTS hashes; DROP TABLE IF EXISTS algorithms;";
			stmt.executeUpdate(sql_dropTables);
			String sql_createAlgoTable = "CREATE TABLE algorithms (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, Name TEXT NOT NULL)";
			stmt.executeUpdate(sql_createAlgoTable);
			String sql_createParamTable = "CREATE TABLE params (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, value TEXT NOT NULL)";
			stmt.executeUpdate(sql_createParamTable);
			String sql_createHashTable = "CREATE TABLE hashes (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, algorithmID INTEGER NOT NULL, paramID INTEGER, value TEXT NOT NULL)";
			stmt.executeUpdate(sql_createHashTable);
			stdOut.println(" + Adding " + config.hashAlgorithms.size() + " hash algorithms to DB.");
			Collections.reverse(config.hashAlgorithms); //so the db has ascending order
			String sql_insertAlgo = "INSERT OR REPLACE INTO algorithms(name, ID) VALUES (?, ?)";
			for (HashAlgorithm algo : config.hashAlgorithms)
			{
				pstmt = conn.prepareStatement(sql_insertAlgo);
				pstmt.setString(1, algo.name.text);
				pstmt.setString(2, Integer.toString(algo.id));
				pstmt.executeUpdate();
				stdOut.println(" + Adding Hash Algorithm to DB: " + algo.name.text + ", " + algo.id);
			}
			Collections.reverse(config.hashAlgorithms); //back to descending order for hash searching
			stdOut.println(moduleName + ": Database initialized.");
			return true;
		} 
		catch (SQLException e) 
		{
			stdErr.println(e.getMessage());
			return false;
		}
		catch (Exception ex)
		{
			stdErr.println(ex);
			return false;
		}
	}
		
	boolean saveParam(String paramValue) 
	{
		int paramId = getParamId(paramValue);
		if (paramId > 0)
		{
			//if (config.debug) stdOut.println(moduleName + ": Not saving parameter (" + paramValue +") since it's already in the db at index = " + paramId);
			return false;
		}
		try 
		{
			if (conn == null) 
			{
				conn = getConnection();
			}
			String sql_insertParam = "INSERT OR REPLACE INTO params(value) VALUES (?)";
			pstmt = conn.prepareStatement(sql_insertParam);
			pstmt.setString(1, paramValue);
			pstmt.executeUpdate();
			stdOut.println(moduleName + ": Saving Discovered Parameter Value: " + paramValue);
			return true;
		} 
		catch (SQLException e) 
		{
			stdErr.println(e.getMessage());
			return false;
		}
	}
	
	int getParamId(String paramValue)
	{
		try 
		{
			if (conn == null) 
			{
				conn = getConnection();
			}
			String sql_paramExists = "SELECT * from params where value = ?";
			pstmt = conn.prepareStatement(sql_paramExists);
			pstmt.setString(1, paramValue);
			ResultSet rs = pstmt.executeQuery();
			if (!rs.next()) 
			{
				return 0;
			}
			int id = rs.getInt("id");
			if (config.debug) stdOut.println(moduleName + ": Found '" + paramValue + "' in the db at index=" + id);
			return id;
		} 
		catch (SQLException e) 
		{
			stdErr.println(moduleName + ": SQLException: " + e);
			return -1;
		}
	}
		
	String getParamByHash(HashRecord hash)
	{
		try 
		{
			if (conn == null) 
			{
				conn = getConnection();
			}
			String sql_paramExists = "select params.value from hashes inner join params on hashes.paramID=params.ID where hashes.algorithmid = ? and hashes.value = ?";
			pstmt = conn.prepareStatement(sql_paramExists);
			pstmt.setString(1, Integer.toString(hash.algorithm.id));
			pstmt.setString(2, hash.getNormalizedRecord());
			ResultSet rs = pstmt.executeQuery();
			if (!rs.next()) 
			{
				return null;
			}
			String paramValue = rs.getString("value");
			if (config.debug) stdOut.println(moduleName + ": Match '" + paramValue + "' for '" + hash.getNormalizedRecord() +"'");
			return paramValue;
		} 
		catch (SQLException e) 
		{
			stdErr.println(moduleName + ": SQLException: " + e);
			return null;
		}
	}	
	
	boolean saveParamWithHash(ParameterWithHash parmWithHash) 
	{
		int paramId = getParamId(parmWithHash.parameter.value);
		if (paramId <= 0)
		{
			if (config.debug) stdOut.println(moduleName + ": Cannot save hash " + parmWithHash.hashedValue + " until the following parameter is saved " + parmWithHash.parameter.value);
			saveParam(parmWithHash.parameter.value);
			paramId = getParamId(parmWithHash.parameter.value);
		}
		try 
		{
			if (conn == null) 
			{
				conn = getConnection();
			}
			int algorithmId = config.getHashId(parmWithHash.algorithm);
			if (algorithmId <= 0)
			{
				stdErr.println(moduleName + ": Could not locate Algorithm ID for " + parmWithHash.algorithm);
				return false;
			}
			String sql_insertHash = "INSERT OR REPLACE INTO hashes(algorithmID, paramID, value) VALUES (?, ?, ?)";
			pstmt = conn.prepareStatement(sql_insertHash);
			pstmt.setString(1, Integer.toString(algorithmId));
			pstmt.setString(2, Integer.toString(paramId));
			pstmt.setString(3, parmWithHash.hashedValue.toLowerCase()); 
			pstmt.executeUpdate();
			if (config.debug) stdOut.println(moduleName + ": Saved " + parmWithHash.algorithm.text + " hash in db: " + parmWithHash.parameter.value + ":" + parmWithHash.hashedValue);
			return true;
		} 
		catch (SQLException e) 
		{
			stdErr.println(moduleName + ": SQLException: " + e);
			return false;
		}
	}
	
	boolean saveHash(HashRecord hash) 
	{
		if (getHashIdByValue(hash.getNormalizedRecord()) > 0)
		{
			//stdOut.println(moduleName + ": Not saving hash (" + hash.getNormalizedRecord() + ") since it's already in the db.");
			return false;
		}
		try 
		{
			if (conn == null) 
			{
				conn = getConnection();
			}
			String sql_insertHash = "INSERT OR REPLACE INTO hashes(algorithmID, value) VALUES (?, ?)";
			pstmt = conn.prepareStatement(sql_insertHash);
			pstmt.setString(1, Integer.toString(hash.algorithm.id));
			pstmt.setString(2, hash.getNormalizedRecord());
			pstmt.executeUpdate();
			stdOut.println(moduleName + ": Saving " + hash.algorithm.name.text + " hash of unknown source value in db: " + hash.getNormalizedRecord());
			return true;
		} 
		catch (SQLException e) 
		{
			stdErr.println(moduleName + ": SQLException: " + e);
			return false;
		}
	}
	
	int getHashIdByValue(String hashedValue)
	{
		try 
		{
			if (conn == null) 
			{
				conn = getConnection();
			}
			String sql_hashExists = "SELECT * from hashes where value = ?";
			pstmt = conn.prepareStatement(sql_hashExists);
			pstmt.setString(1, hashedValue);
			ResultSet rs = pstmt.executeQuery();
			if (!rs.next()) 
			{
				return 0;
			}
			int id = rs.getInt("id");
			if (config.debug) stdOut.println(moduleName + ": Found '" + hashedValue + "' in the db at index=" + id);
			return id;
		} 
		catch (SQLException e) 
		{
			stdErr.println(moduleName + ": SQLException: " + e);
			return -1;
		}
	}

	/**
	 * TODO: verify presence of all tables? (params, hashes, etc.) < Yes please, but !MVP [TM]
	 */
	boolean verify() 
	{
		Statement stmt = null;
		ResultSet rs = null;

		try 
		{
			if (conn == null) 
			{
				conn = getConnection();
			}
			stmt = conn.createStatement();
			stmt.setQueryTimeout(30);
			String sql_tableCheck = "SELECT name FROM sqlite_master WHERE type='table' AND name='params';";
			rs = stmt.executeQuery(sql_tableCheck);
			boolean x = false;
			while (rs.next()) 
			{
				x = true;
			}
			return x;
		} 
		catch (SQLException e) 
		{
			stdErr.println(moduleName + ": SQLException: " + e);
			return false;
		}
	}

	/**
	 * TODO: This is to return the list of parameters that were saved without HashAlgorithm.Name hashes.
	 * In other words, pump this list out, hash them against 'algorithm' and save them back to the DB for
	 * future comparisons.
	 * @param algorithm
	 * @return
	 */
	public List<String> getParamsWithoutHashType(HashAlgorithm algorithm) 
	{
		List<String> params = new ArrayList<>();
		//TODO: Need to fix this query - want to find all the params that don't have a hash table entry with algorithm ID matching the algorithm passed to this method:
		String sql_selectMissing = "select ID, VALUE from params where ID not in (select paramID from hashes where hashes.algorithmID = ?)";
		try 
		{
			pstmt = conn.prepareStatement(sql_selectMissing);
			pstmt.setString(1, Integer.toString(algorithm.id));
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) 
			{
				//int paramId = rs.getInt("id");
				String value = rs.getString("value");
				params.add(value);
			}
		} 
		catch (SQLException e) 
		{
			stdErr.println(moduleName + ": SQL Exception: " + e);
		}
		return params;
	}
}