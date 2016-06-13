#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pstore.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_ids.h>
#include <uapi/linux/virtio_pstore.h>

#define VIRT_PSTORE_ORDER    2
#define VIRT_PSTORE_BUFSIZE  (4096 << VIRT_PSTORE_ORDER)

struct virtio_pstore {
	struct virtio_device	*vdev;
	struct virtqueue	*vq;
	struct pstore_info	 pstore;
	struct virtio_pstore_hdr hdr;
	size_t			 buflen;
	u64			 id;

	/* Waiting for host to ack */
	wait_queue_head_t	acked;
};

static u16 to_virtio_type(struct virtio_pstore *vps, enum pstore_type_id type)
{
	u16 ret;

	switch (type) {
	case PSTORE_TYPE_DMESG:
		ret = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_TYPE_DMESG);
		break;
	default:
		ret = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_TYPE_UNKNOWN);
		break;
	}

	return ret;
}

static enum pstore_type_id from_virtio_type(struct virtio_pstore *vps, u16 type)
{
	enum pstore_type_id ret;

	switch (virtio16_to_cpu(vps->vdev, type)) {
	case VIRTIO_PSTORE_TYPE_DMESG:
		ret = PSTORE_TYPE_DMESG;
		break;
	default:
		ret = PSTORE_TYPE_UNKNOWN;
		break;
	}

	return ret;
}

static void virtpstore_ack(struct virtqueue *vq)
{
	struct virtio_pstore *vps = vq->vdev->priv;

	wake_up(&vps->acked);
}

static int virt_pstore_open(struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_hdr *hdr = &vps->hdr;
	struct scatterlist sg[1];
	unsigned int len;

	hdr->cmd = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_OPEN);

	sg_init_one(sg, hdr, sizeof(*hdr));
	virtqueue_add_outbuf(vps->vq, sg, 1, vps, GFP_KERNEL);
	virtqueue_kick(vps->vq);

	wait_event(vps->acked, virtqueue_get_buf(vps->vq, &len));
	return 0;
}

static int virt_pstore_close(struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_hdr *hdr = &vps->hdr;
	struct scatterlist sg[1];
	unsigned int len;

	hdr->cmd = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_CLOSE);

	sg_init_one(sg, hdr, sizeof(*hdr));
	virtqueue_add_outbuf(vps->vq, sg, 1, vps, GFP_KERNEL);
	virtqueue_kick(vps->vq);

	wait_event(vps->acked, virtqueue_get_buf(vps->vq, &len));
	return 0;
}

static ssize_t virt_pstore_read(u64 *id, enum pstore_type_id *type,
				int *count, struct timespec *time,
				char **buf, bool *compressed,
				struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_hdr *hdr = &vps->hdr;
	struct scatterlist sgi[1], sgo[1];
	struct scatterlist *sgs[2] = { sgo, sgi };
	unsigned int len;
	unsigned int flags;
	void *bf;

	hdr->cmd = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_READ);

	sg_init_one(sgo, hdr, sizeof(*hdr));
	sg_init_one(sgi, psi->buf, psi->bufsize);
	virtqueue_add_sgs(vps->vq, sgs, 1, 1, vps, GFP_KERNEL);
	virtqueue_kick(vps->vq);

	wait_event(vps->acked, virtqueue_get_buf(vps->vq, &len));
	if (len == 0)
		return 0;

	bf = kmalloc(len, GFP_KERNEL);
	if (bf == NULL)
		return -ENOMEM;

	*id = virtio64_to_cpu(vps->vdev, hdr->id);
	*type = from_virtio_type(vps, hdr->type);

	flags = virtio32_to_cpu(vps->vdev, hdr->flags);
	*compressed = flags & VIRTIO_PSTORE_FL_COMPRESSED;
	*count = 1;

	time->tv_sec  = virtio64_to_cpu(vps->vdev, hdr->time_sec);
	time->tv_nsec = virtio32_to_cpu(vps->vdev, hdr->time_nsec);

	memcpy(bf, psi->buf, len);
	*buf = bf;

	return len;
}

static int notrace virt_pstore_write(enum pstore_type_id type,
				     enum kmsg_dump_reason reason,
				     u64 *id, unsigned int part, int count,
				     bool compressed, size_t size,
				     struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_hdr *hdr = &vps->hdr;
	struct scatterlist sg[2];
	unsigned int flags = compressed ? VIRTIO_PSTORE_FL_COMPRESSED : 0;

	*id = vps->id++;

	hdr->cmd   = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_WRITE);
	hdr->id	   = cpu_to_virtio64(vps->vdev, *id);
	hdr->flags = cpu_to_virtio32(vps->vdev, flags);
	hdr->type  = to_virtio_type(vps, type);

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], hdr, sizeof(*hdr));
	sg_set_buf(&sg[1], psi->buf, size);
	virtqueue_add_outbuf(vps->vq, sg, 2, vps, GFP_ATOMIC);
	virtqueue_kick(vps->vq);

	/* TODO: make it synchronous */
	return 0;
}

static int virt_pstore_erase(enum pstore_type_id type, u64 id, int count,
			     struct timespec time, struct pstore_info *psi)
{
	struct virtio_pstore *vps = psi->data;
	struct virtio_pstore_hdr *hdr = &vps->hdr;
	struct scatterlist sg[1];
	unsigned int len;

	hdr->cmd   = cpu_to_virtio16(vps->vdev, VIRTIO_PSTORE_CMD_ERASE);
	hdr->id	   = cpu_to_virtio64(vps->vdev, id);
	hdr->type  = to_virtio_type(vps, type);

	sg_init_one(sg, hdr, sizeof(*hdr));
	virtqueue_add_outbuf(vps->vq, sg, 1, vps, GFP_KERNEL);
	virtqueue_kick(vps->vq);

	wait_event(vps->acked, virtqueue_get_buf(vps->vq, &len));
	return 0;
}

static int virt_pstore_init(struct virtio_pstore *vps)
{
	struct pstore_info *psinfo = &vps->pstore;
	int err;

	vps->id = 0;
	vps->buflen = 0;
	psinfo->bufsize = VIRT_PSTORE_BUFSIZE;
	psinfo->buf = (void *)__get_free_pages(GFP_KERNEL, VIRT_PSTORE_ORDER);
	if (!psinfo->buf) {
		pr_err("cannot allocate pstore buffer\n");
		return -ENOMEM;
	}

	psinfo->owner = THIS_MODULE;
	psinfo->name  = "virtio";
	psinfo->open  = virt_pstore_open;
	psinfo->close = virt_pstore_close;
	psinfo->read  = virt_pstore_read;
	psinfo->erase = virt_pstore_erase;
	psinfo->write = virt_pstore_write;
	psinfo->flags = PSTORE_FLAGS_FRAGILE;
	psinfo->data  = vps;
	spin_lock_init(&psinfo->buf_lock);

	err = pstore_register(psinfo);
	if (err)
		kfree(psinfo->buf);

	return err;
}

static int virt_pstore_exit(struct virtio_pstore *vps)
{
	struct pstore_info *psinfo = &vps->pstore;

	pstore_unregister(psinfo);

	free_pages((unsigned long)psinfo->buf, VIRT_PSTORE_ORDER);
	psinfo->bufsize = 0;

	return 0;
}

static int virtpstore_probe(struct virtio_device *vdev)
{
	struct virtio_pstore *vps;
	int err;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	vdev->priv = vps = kmalloc(sizeof(*vps), GFP_KERNEL);
	if (!vps) {
		err = -ENOMEM;
		goto out;
	}

	vps->vdev = vdev;

	vps->vq = virtio_find_single_vq(vdev, virtpstore_ack, "pstore");
	if (IS_ERR(vps->vq)) {
		err = PTR_ERR(vps->vq);
		goto out_free;
	}

	err = virt_pstore_init(vps);
	if (err)
		goto out_del_vq;

	init_waitqueue_head(&vps->acked);

	virtio_device_ready(vdev);
	dev_info(&vdev->dev, "virtio pstore driver init: ok\n");

	return 0;

out_del_vq:
	vdev->config->del_vqs(vdev);
out_free:
	kfree(vps);
out:
	dev_err(&vdev->dev, "virtio pstore driver init: failed with %d\n", err);
	return err;
}

static void virtpstore_remove(struct virtio_device *vdev)
{
	struct virtio_pstore *vps = vdev->priv;

	virt_pstore_exit(vps);

	/* Now we reset the device so we can clean up the queues. */
	vdev->config->reset(vdev);

	vdev->config->del_vqs(vdev);

	kfree(vps);
}

static unsigned int features[] = {
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_PSTORE, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_pstore_driver = {
	.driver.name         = KBUILD_MODNAME,
	.driver.owner        = THIS_MODULE,
	.feature_table       = features,
	.feature_table_size  = ARRAY_SIZE(features),
	.id_table            = id_table,
	.probe               = virtpstore_probe,
	.remove              = virtpstore_remove,
};

module_virtio_driver(virtio_pstore_driver);
MODULE_DEVICE_TABLE(virtio, id_table);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Namhyung Kim <namhyung@kernel.org>");
MODULE_DESCRIPTION("Virtio pstore driver");
