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
		type = ItemType.PARAMETER;
		item = p;
	}

	Item(ICookie c) {
		type = ItemType.COOKIE;
		item = c;
	}
	
	Item(String s) 
	{
		type = ItemType.VALUE_ONLY;
		item = s;
	}

	Object getItem() {
		return item;
	}

	ItemType getItemType() {
		return type;
	}

	// Methods common to both interfaces
	@Override
	public String getName() 
 	{
		switch (type)
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
		switch (type)
		{
			case COOKIE:
				if (value == null) return ((ICookie) item).getValue();
				return value;
			case PARAMETER:
				if (value == null) return ((IParameter) item).getValue();
				return value;
			case VALUE_ONLY:
				return value;
		}
		return null;
	}
	
	public void setValue(String s)
	{
		value = s;
	}
	
	// ICookie methods
	@Override
	public String getDomain() {
		if (getItemType().equals(ItemType.COOKIE)) {
			return ((ICookie) item).getDomain();
		} else {
			return null;
		}
	}

	@Override
	public Date getExpiration() {
		if (getItemType().equals(ItemType.COOKIE)) {
			return ((ICookie) item).getExpiration();
		} else {
			return null;
		}
	}

	// IParameter methods
	@Override
	public byte getType() {
		if (getItemType().equals(ItemType.PARAMETER)) {
			return ((IParameter) item).getType();
		} else {
			return -1;
		}
	}

	@Override
	public int getNameStart() {
		if (getItemType().equals(ItemType.PARAMETER)) {
			return ((IParameter) item).getNameStart();
		} else {
			return -1;
		}
	}

	@Override
	public int getNameEnd() {
		if (getItemType().equals(ItemType.PARAMETER)) {
			return ((IParameter) item).getNameEnd();
		} else {
			return -1;
		}
	}

	@Override
	public int getValueStart() {
		if (getItemType().equals(ItemType.PARAMETER)) {
			return ((IParameter) item).getValueStart();
		} else {
			return -1;
		}
	}

	@Override
	public int getValueEnd() {
		if (getItemType().equals(ItemType.PARAMETER)) {
			return ((IParameter) item).getValueEnd();
		} else {
			return -1;
		}
	}
}