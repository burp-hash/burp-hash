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
			return ((ICookie)item).getName();
		} else {
			return ((IParameter)item).getName();
		}
	}

	@Override
	public String getValue() {
		return ((Item)item).getValue();
	}

	// ICookie methods
	@Override
	public String getDomain() {
		return ((Item)item).getDomain();
	}

	@Override
	public Date getExpiration() {
		return ((Item)item).getExpiration();
	}

	// IParameter methods
	@Override
	public byte getType() {
		return ((Item)item).getType();
	}

	@Override
	public int getNameStart() {
		return ((Item)item).getNameStart();
	}

	@Override
	public int getNameEnd() {
		return ((Item)item).getNameEnd();
	}

	@Override
	public int getValueStart() {
		return ((Item)item).getValueStart();
	}

	@Override
	public int getValueEnd() {
		return ((Item)item).getValueEnd();
	}
}