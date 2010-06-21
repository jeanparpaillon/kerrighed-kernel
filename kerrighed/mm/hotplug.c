/** Implementation of memory related hotplug mechanisms.
 *  @file hotplug.c
 *
 *  Copyright (C) 2009, Renaud Lottiaux, Kerlabs.
 */

int mm_notification(struct notifier_block *nb, hotplug_event_t event,
		    void *data)
{
	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		/* Nothing to do */
		break;

	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		break;

	case HOTPLUG_NOTIFY_REMOVE_ADVERT:
		/* Nothing to do */
		break;

	case HOTPLUG_NOTIFY_REMOVE_DISTANT:
		/* Nothing to do */
		break;

	case HOTPLUG_NOTIFY_REMOVE_ACK:
		/* Nothing to do */
		break;

	case HOTPLUG_NOTIFY_FAIL:
		/* Not yet managed */
		BUG();

	default:
		BUG();
	}

	return NOTIFY_OK;

}
