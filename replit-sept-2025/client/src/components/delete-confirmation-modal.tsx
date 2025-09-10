import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { AlertTriangle, Shield, Trash2 } from "lucide-react";

interface DeleteConfirmationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  isDeleting?: boolean;
}

export function DeleteConfirmationModal({
  isOpen,
  onClose,
  onConfirm,
  isDeleting = false,
}: DeleteConfirmationModalProps) {
  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-md" data-testid="modal-delete-confirmation">
        <DialogHeader>
          <DialogTitle className="flex items-center">
            <AlertTriangle className="text-destructive mr-3 h-5 w-5" />
            Confirm Deletion
          </DialogTitle>
          <DialogDescription>
            Are you sure you want to delete this note? This action cannot be undone and will permanently remove the note from our secure servers.
          </DialogDescription>
        </DialogHeader>

        <div className="bg-amber-50 border border-amber-200 rounded-md p-3 my-4">
          <div className="flex items-center text-amber-700 text-sm">
            <Shield className="h-4 w-4 mr-2" />
            <span>Secure deletion will be performed with data wiping</span>
          </div>
        </div>

        <DialogFooter className="flex space-x-3">
          <Button 
            variant="outline" 
            onClick={onClose}
            disabled={isDeleting}
            data-testid="button-cancel-delete"
          >
            Cancel
          </Button>
          <Button 
            variant="destructive" 
            onClick={onConfirm}
            disabled={isDeleting}
            data-testid="button-confirm-delete"
          >
            <Trash2 className="h-4 w-4 mr-2" />
            {isDeleting ? "Deleting..." : "Delete Permanently"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
