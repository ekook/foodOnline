from django.db.models.signals import post_save
from django.dispatch import receiver

from accounts.models import UserProfile, User


@receiver(post_save, sender=User)
def post_save_create_profile_receiver(sender, instance, created, **kwargs):
    print(created)
    if created:
        UserProfile.objects.create(user=instance)
        print('user profile is created')
    else:
        try:
            profile = UserProfile.objects.get(user=instance)
            profile.save()
            print('user is updated')
        except:
            UserProfile.objects.create(user=instance)



# post_save.connect(post_save_create_profile_receiver, sender=User)
