package burp;

import java.util.Date;

/**
 * This implementation of {@link ICookie}, {@link IParameter}, and {@link IBurpHashParameter} is used to homogenize the
 * object types during processing.
 */
class Item implements ICookie, IParameter {
	private ItemType type;
	private Object item;
	private String value = null;

	Item(IParameter p) {
		this.type = ItemType.PARAMETER;
		this.item = p;
	}

	Item(ICookie c) {
		this.type = ItemType.COOKIE;
		this.item = c;
	}
	
	Item(String s) 
	{
		this.type = ItemType.VALUE_ONLY;
		this.item = s;
	}

	Object getItem() {
		return item;
	}

	ItemType getItemType() {
		return this.type;
	}

	// Methods common to both interfaces
	@Override
	public String getName() 
 	{
		switch (this.type)
		{
			case COOKIE:
				return ((ICookie) item).getName();
			case PARAMETER:
				return ((IParameter) item).getName();
			case VALUE_ONLY:
				return ((String) "");
		}
		return null;
 	}

	@Override
	public String getValue() 
	{
		switch (this.type)
		{
			case COOKIE:
				if (this.value == null) return ((ICookie) item).getValue();
				return this.value;
			case PARAMETER:
				if (this.value == null) return ((IParameter) item).getValue();
				return this.value;
			case VALUE_ONLY:
				return this.value;
		}
		return null;
	}
	
	public void setValue(String s)
	{
		this.value = s;
	}
	
	// ICookie methods
	@Override
	public String getDomain() {
		if (this.getItemType() == ItemType.COOKIE) {
			return ((ICookie) item).getDomain();
		} else {
			return null;
		}
	}

	@Override
	public Date getExpiration() {
		if (this.getItemType() == ItemType.COOKIE) {
			return ((ICookie) item).getExpiration();
		} else {
			return null;
		}
	}

	// IParameter methods
	@Override
	public byte getType() {
		if (this.getItemType() == ItemType.PARAMETER) {
			return ((IParameter) item).getType();
		} else {
			return -1;
		}
	}

	@Override
	public int getNameStart() {
		if (this.getItemType() == ItemType.PARAMETER) {
			return ((IParameter) item).getNameStart();
		} else {
			return -1;
		}
	}

	@Override
	public int getNameEnd() {
		if (this.getItemType() == ItemType.PARAMETER) {
			return ((IParameter) item).getNameEnd();
		} else {
			return -1;
		}
	}

	@Override
	public int getValueStart() {
		if (this.getItemType() == ItemType.PARAMETER) {
			return ((IParameter) item).getValueStart();
		} else {
			return -1;
		}
	}

	@Override
	public int getValueEnd() {
		if (this.getItemType() == ItemType.PARAMETER) {
			return ((IParameter) item).getValueEnd();
		} else {
			return -1;
		}
	}
}