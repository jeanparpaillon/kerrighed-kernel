/*
 * USB Driver for ALi m5602 based webcams
 *
 * Copyright (C) 2008 Erik Andren
 * Copyright (C) 2007 Ilyes Gouta. Based on the m5603x Linux Driver Project.
 * Copyright (C) 2005 m5603x Linux Driver Project <m5602@x3ng.com.br>
 *
 * Portions of code to USB interface and ALi driver software,
 * Copyright (c) 2006 Willem Duinker
 * v4l2 interface modeled after the V4L2 driver
 * for SN9C10x PC Camera Controllers
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2.
 *
 */

#include "m5602_ov9650.h"
#include "m5602_mt9m111.h"
#include "m5602_po1030.h"
#include "m5602_s5k83a.h"
#include "m5602_s5k4aa.h"

/* Kernel module parameters */
int force_sensor;
int dump_bridge;
int dump_sensor;
unsigned int m5602_debug;

static const __devinitdata struct usb_device_id m5602_table[] = {
	{USB_DEVICE(0x0402, 0x5602)},
	{}
};

MODULE_DEVICE_TABLE(usb, m5602_table);

/* Reads a byte from the m5602 */
int m5602_read_bridge(struct sd *sd, u8 address, u8 *i2c_data)
{
	int err;
	struct usb_device *udev = sd->gspca_dev.dev;
	__u8 *buf = sd->gspca_dev.usb_buf;

	err = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      0x04, 0xc0, 0x14,
			      0x8100 + address, buf,
			      1, M5602_URB_MSG_TIMEOUT);
	*i2c_data = buf[0];

	PDEBUG(DBG_TRACE, "Reading bridge register 0x%x containing 0x%x",
	       address, *i2c_data);

	/* usb_control_msg(...) returns the number of bytes sent upon success,
	mask that and return zero upon success instead*/
	return (err < 0) ? err : 0;
}

/* Writes a byte to to the m5602 */
int m5602_write_bridge(struct sd *sd, u8 address, u8 i2c_data)
{
	int err;
	struct usb_device *udev = sd->gspca_dev.dev;
	__u8 *buf = sd->gspca_dev.usb_buf;

	PDEBUG(DBG_TRACE, "Writing bridge register 0x%x with 0x%x",
	       address, i2c_data);

	memcpy(buf, bridge_urb_skeleton,
	       sizeof(bridge_urb_skeleton));
	buf[1] = address;
	buf[3] = i2c_data;

	err = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				0x04, 0x40, 0x19,
				0x0000, buf,
				4, M5602_URB_MSG_TIMEOUT);

	/* usb_control_msg(...) returns the number of bytes sent upon success,
	   mask that and return zero upon success instead */
	return (err < 0) ? err : 0;
}

/* Dump all the registers of the m5602 bridge,
   unfortunately this breaks the camera until it's power cycled */
static void m5602_dump_bridge(struct sd *sd)
{
	int i;
	for (i = 0; i < 0x80; i++) {
		unsigned char val = 0;
		m5602_read_bridge(sd, i, &val);
		info("ALi m5602 address 0x%x contains 0x%x", i, val);
	}
	info("Warning: The camera probably won't work until it's power cycled");
}

static int m5602_probe_sensor(struct sd *sd)
{
	/* Try the po1030 */
	sd->sensor = &po1030;
	if (!sd->sensor->probe(sd))
		return 0;

	/* Try the mt9m111 sensor */
	sd->sensor = &mt9m111;
	if (!sd->sensor->probe(sd))
		return 0;

	/* Try the s5k4aa */
	sd->sensor = &s5k4aa;
	if (!sd->sensor->probe(sd))
		return 0;

	/* Try the ov9650 */
	sd->sensor = &ov9650;
	if (!sd->sensor->probe(sd))
		return 0;

	/* Try the s5k83a */
	sd->sensor = &s5k83a;
	if (!sd->sensor->probe(sd))
		return 0;

	/* More sensor probe function goes here */
	info("Failed to find a sensor");
	sd->sensor = NULL;
	return -ENODEV;
}

static int m5602_configure(struct gspca_dev *gspca_dev,
			   const struct usb_device_id *id);

static int m5602_init(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	int err;

	PDEBUG(DBG_TRACE, "Initializing ALi m5602 webcam");
	/* Run the init sequence */
	err = sd->sensor->init(sd);

	return err;
}

static int m5602_start_transfer(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	__u8 *buf = sd->gspca_dev.usb_buf;

	/* Send start command to the camera */
	const u8 buffer[4] = {0x13, 0xf9, 0x0f, 0x01};
	memcpy(buf, buffer, sizeof(buffer));
	usb_control_msg(gspca_dev->dev, usb_sndctrlpipe(gspca_dev->dev, 0),
			0x04, 0x40, 0x19, 0x0000, buf,
			4, M5602_URB_MSG_TIMEOUT);

	PDEBUG(DBG_V4L2, "Transfer started");
	return 0;
}

static void m5602_urb_complete(struct gspca_dev *gspca_dev,
			struct gspca_frame *frame,
			__u8 *data, int len)
{
	struct sd *sd = (struct sd *) gspca_dev;

	if (len < 6) {
		PDEBUG(DBG_DATA, "Packet is less than 6 bytes");
		return;
	}

	/* Frame delimiter: ff xx xx xx ff ff */
	if (data[0] == 0xff && data[4] == 0xff && data[5] == 0xff &&
	    data[2] != sd->frame_id) {
		PDEBUG(DBG_DATA, "Frame delimiter detected");
		sd->frame_id = data[2];

		/* Remove the extra fluff appended on each header */
		data += 6;
		len -= 6;

		/* Complete the last frame (if any) */
		frame = gspca_frame_add(gspca_dev, LAST_PACKET,
					frame, data, 0);
		sd->frame_count++;

		/* Create a new frame */
		gspca_frame_add(gspca_dev, FIRST_PACKET, frame, data, len);

		PDEBUG(DBG_V4L2, "Starting new frame %d",
		       sd->frame_count);

	} else {
		int cur_frame_len = frame->data_end - frame->data;

		/* Remove urb header */
		data += 4;
		len -= 4;

		if (cur_frame_len + len <= frame->v4l2_buf.length) {
			PDEBUG(DBG_DATA, "Continuing frame %d copying %d bytes",
			       sd->frame_count, len);

			gspca_frame_add(gspca_dev, INTER_PACKET, frame,
					data, len);
		} else if (frame->v4l2_buf.length - cur_frame_len > 0) {
			/* Add the remaining data up to frame size */
			gspca_frame_add(gspca_dev, INTER_PACKET, frame, data,
					frame->v4l2_buf.length - cur_frame_len);
		}
	}
}

static void m5602_stop_transfer(struct gspca_dev *gspca_dev)
{
	/* Is there are a command to stop a data transfer? */
}

/* sub-driver description, the ctrl and nctrl is filled at probe time */
static struct sd_desc sd_desc = {
	.name		= MODULE_NAME,
	.config		= m5602_configure,
	.init		= m5602_init,
	.start		= m5602_start_transfer,
	.stopN		= m5602_stop_transfer,
	.pkt_scan	= m5602_urb_complete
};

/* this function is called at probe time */
static int m5602_configure(struct gspca_dev *gspca_dev,
			   const struct usb_device_id *id)
{
	struct sd *sd = (struct sd *) gspca_dev;
	struct cam *cam;
	int err;

	PDEBUG(DBG_GSPCA, "m5602_configure start");

	cam = &gspca_dev->cam;
	cam->epaddr = M5602_ISOC_ENDPOINT_ADDR;
	sd->desc = &sd_desc;

	if (dump_bridge)
		m5602_dump_bridge(sd);

	/* Probe sensor */
	err = m5602_probe_sensor(sd);
	if (err)
		goto fail;

	PDEBUG(DBG_GSPCA, "m5602_configure end");
	return 0;

fail:
	PDEBUG(DBG_GSPCA, "m5602_configure failed");
	cam->cam_mode = NULL;
	cam->nmodes = 0;

	return err;
}

static int m5602_probe(struct usb_interface *intf,
		       const struct usb_device_id *id)
{
	return gspca_dev_probe(intf, id, &sd_desc, sizeof(struct sd),
			       THIS_MODULE);
}

static struct usb_driver sd_driver = {
	.name = MODULE_NAME,
	.id_table = m5602_table,
	.probe = m5602_probe,
#ifdef CONFIG_PM
	.suspend = gspca_suspend,
	.resume = gspca_resume,
#endif
	.disconnect = gspca_disconnect
};

/* -- module insert / remove -- */
static int __init mod_m5602_init(void)
{
	if (usb_register(&sd_driver) < 0)
		return -1;
	PDEBUG(D_PROBE, "m5602 module registered");
	return 0;
}
static void __exit mod_m5602_exit(void)
{
	usb_deregister(&sd_driver);
	PDEBUG(D_PROBE, "m5602 module deregistered");
}

module_init(mod_m5602_init);
module_exit(mod_m5602_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
module_param_named(debug, m5602_debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "toggles debug on/off");

module_param(force_sensor, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(force_sensor,
		"force detection of sensor, "
		"1 = OV9650, 2 = S5K83A, 3 = S5K4AA, 4 = MT9M111, 5 = PO1030");

module_param(dump_bridge, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dump_bridge, "Dumps all usb bridge registers at startup");

module_param(dump_sensor, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dump_sensor, "Dumps all usb sensor registers "
		"at startup providing a sensor is found");