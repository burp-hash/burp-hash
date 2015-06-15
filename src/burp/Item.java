package burp;

import java.util.Date;

/**
 * This implementation of ICookie and IParameter is used to homogenize the two
 * object types during processing.
 */
class Item implements ICookie, IParameter {
	public static final int COOKIE = 1;
	public static final int PARAMETER = 0;
	private int type;
	private Object item;

	public Item(IParameter p) {
		this.type = PARAMETER;
		this.item = p;
	}

	public Item(ICookie c) {
		this.type = COOKIE;
		this.item = c;
	}

	public Object getItem() {
		return item;
	}

	public int getItemType() {
		return type;
	}

	// Methods common to both interfaces
	@Override
	public String getName() {
		if (this.getItemType() == Item.COOKIE) {
			return ((ICookie) item).getName();
		} else {
			return ((IParameter) item).getName();
		}
	}

	@Override
	public String getValue() {
		if (this.getItemType() == Item.COOKIE) {
			return ((ICookie) item).getValue();
		} else {
			return ((IParameter) item).getValue();
		}
	}

	// ICookie methods
	@Override
	public String getDomain() {
		if (this.getItemType() == Item.COOKIE) {
			return ((ICookie) item).getDomain();
		} else {
			return null;
		}
	}

	@Override
	public Date getExpiration() {
		if (this.getItemType() == Item.COOKIE) {
			return ((ICookie) item).getExpiration();
		} else {
			return null;
		}
	}

	// IParameter methods
	@Override
	public byte getType() {
		if (this.getItemType() == Item.PARAMETER) {
			return ((IParameter) item).getType();
		} else {
			return -1;
		}
	}

	@Override
	public int getNameStart() {
		if (this.getItemType() == Item.PARAMETER) {
			return ((IParameter) item).getNameStart();
		} else {
			return -1;
		}
	}

	@Override
	public int getNameEnd() {
		if (this.getItemType() == Item.PARAMETER) {
			return ((IParameter) item).getNameEnd();
		} else {
			return -1;
		}
	}

	@Override
	public int getValueStart() {
		if (this.getItemType() == Item.PARAMETER) {
			return ((IParameter) item).getValueStart();
		} else {
			return -1;
		}
	}

	@Override
	public int getValueEnd() {
		if (this.getItemType() == Item.PARAMETER) {
			return ((IParameter) item).getValueEnd();
		} else {
			return -1;
		}
	}
}